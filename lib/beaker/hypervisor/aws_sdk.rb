require 'aws/ec2'
require 'set'
require 'zlib'

module Beaker
  # This is an alternate EC2 driver that implements direct API access using
  # Amazon's AWS-SDK library: http://aws.amazon.com/documentation/sdkforruby/
  #
  # It is built for full control, to reduce any other layers beyond the pure
  # vendor API.
  class AwsSdk < Beaker::Hypervisor
    # Initialize AwsSdk hypervisor driver
    #
    # @param [Array<Beaker::Host>] hosts Array of Beaker::Host objects
    # @param [Hash<String, String>] options Options hash
    def initialize(hosts, options)
      @hosts = hosts
      @options = options
      @logger = options[:logger]

      # Get fog credentials from the local .fog file
      creds = load_fog_credentials(@options[:dot_fog])

      config = {
        :access_key_id => creds[:access_key],
        :secret_access_key => creds[:secret_key],
        :logger => Logger.new($stdout),
        :log_level => :debug,
        :log_formatter => AWS::Core::LogFormatter.colored,
      }
      AWS.config(config)

      # TODO: decide what options to pass on new
      @ec2 = AWS::EC2.new()
    end

    # Provision all hosts on EC2 using the AWS::EC2 API.
    #
    # @return [void]
    def provision
      # Load the ec2_yaml spec file
      ami_spec = YAML.load_file(@options[:ec2_yaml])["AMI"]

      # Iterate across all hosts and launch them
      @hosts.each do |host|
        amitype = host['vmname'] || host['platform']
        amisize = host['amisize'] || 'm1.small'

        # Use snapshot provided for this host
        image_type = host['snapshot']
        if not image_type
          raise "No snapshot/image_type provided for EC2 provisioning"
        end
        ami = ami_spec[amitype]
        image_id = ami[:image][image_type.to_sym]

        # Region object
        region = @ec2.regions[ami[:region]]

        # TODO: validate image_id exists first perhaps?

        # Setup a keypair for this host, if one doesn't already exist
        @logger.notify("aws-sdk: Ensure key pair exists, create if not")
        key_pair = ensure_key_pair(region)

        # Grab the security group, creating one if it doesn't exist
        @logger.notify("aws-sdk: Ensure security group exists, create if not")
        security_group = ensure_group(region, amiports(host))

        # TODO: check options that are needed for launching
        @logger.notify("aws-sdk: Launch instance")
        config = {
          :count => 1,
          :image_id => image_id,
          :monitoring_enabled => true,
          :key_pair => key_pair,
          :security_groups => [security_group],
          :instance_type => amisize,
          :disable_api_termination => false,
          :instance_initiated_shutdown_behavior => "terminate",
        }
        instance = region.instances.create(config)

        # Persist the instance object for this host, so later it can be
        # manipulated by 'cleanup' for example.
        host['instance'] = instance

        # Define tags for the instance
        @logger.notify("aws-sdk: Add tags")
        instance.add_tag("jenkins_build_url", :value => @options[:jenkins_build_url])
        instance.add_tag("Name", :value => host.name)
        instance.add_tag("department", :value => @options[:department])
        instance.add_tag("project", :value => @options[:project])

        @logger.notify("aws-sdk: Launched #{host.name} (#{amitype}:#{amisize}) using snapshot/image_type #{image_type}")
      end

      # Configure our nodes to match the blimp fleet
      # Also generate hosts entries for the fleet, since we're iterating
      etc_hosts = "127.0.0.1\tlocalhost localhost.localdomain\n"
      @hosts.each do |host|
        instance = host['instance']

        @logger.notify("aws-sdk: Wait for status :running")

        # TODO: should probably be a in a shared method somewhere
        for tries in 1..10
          if instance.status == :running
            # Always sleep, so the next command won't cause a throttle
            backoff_sleep(tries)
            break
          elsif tries == 10
            raise "Instance never reached state :running"
          end
          backoff_sleep(tries)
        end

        host['ip'] = instance.dns_name
        name = host.name

        # Without this we get 'Unable to authenticate' error message while the
        # machine is still provisioning
        # TODO: similar to retry logic above, merge perhaps and modularize?
        tries = 0
        begin
          tries += 1
          host.exec(Command.new("hostname #{name}"))
        rescue RuntimeError => ex
          if tries <= 10
            backoff_sleep(tries)
            retry
          else
            raise ex
          end
        end

        # Construct a suitable /etc/hosts line entry for this host and append it
        # to the global one
        ip = get_ip(host)
        domain = get_domain_name(host)
        etc_hosts += "#{ip}\t#{name}\t#{name}.#{domain}\n"
      end

      # Send our /etc/hosts information to all nodes
      @hosts.each do |host|
        set_etc_hosts(host, etc_hosts)
      end

      nil #void
    end

    # Cleanup all hosts on EC2
    #
    # @return [void]
    def cleanup
      @hosts.each do |host|
        instance = host['instance']
        if instance.exists?
          instance.terminate
        end
      end

      nil #void
    end

    # Return a list of ports that must be opened for testing
    # based on a hosts role.
    #
    # @todo horribly hard-coded
    # @param [Beaker::Host] host Beaker host object
    # @return [Array<Number>] array of port numbers
    # @api private
    def amiports(host)
      roles = host['roles']
      ports = [22]

      if roles.include? 'database'
        ports << 8080
        ports << 8081
      end

      if roles.include? 'master'
        ports << 8140
      end

      if roles.include? 'dashboard'
        ports << 443
      end

      ports
    end

    # Calculates and waits a back-off period based on the number of tries.
    #
    # @param tries [Number] number of tries to calculate back-off period
    # @return [void]
    # @api private
    def backoff_sleep(tries)
      # Exponential with some randomization
      sleep_time = 2 ** tries
      @logger.notify("aws-sdk: Sleeping #{sleep_time} seconds for attempt #{tries}.")
      sleep sleep_time
      nil
    end

    # Retrieve the public key locally from the executing users ~/.ssh directory
    #
    # @return [String] contents of public key
    # @api private
    def public_key
      filename = File.expand_path('~/.ssh/id_rsa.pub')
      unless File.exists? filename
        filename = File.expand_path('~/.ssh/id_dsa.pub')
        unless File.exists? filename
          raise Blimpy::SSHKeyNotFoundError, 'Expected either ~/.ssh/id_rsa.pub or ~/.ssh/id_dsa.pub but found neither'
        end
      end

      File.open(filename, 'r').read
    end

    # Generate a key name from the local hosts hostname
    #
    # @return [String] safe key name for current host
    # @api private
    def key_name
      safe_hostname = Socket.gethostname.gsub('.', '-')
      "Beaker-#{ENV['USER']}-#{safe_hostname}"
    end

    # Returns the KeyPair for this host, creating it if it doesn't already exist
    #
    # @param region [AWS::EC2::Region] region to create the key pair in
    # @return [AWS::EC2::KeyPair] created key_pair
    # @api private
    def ensure_key_pair(region)
      key_pairs = region.key_pairs
      pair_name = key_name()
      kp = key_pairs[pair_name]
      unless kp.exists?
        ssh_string = public_key()
        kp = key_pairs.import(pair_name, ssh_string)
      end

      kp
    end

    # Return a reproducable security group identifier based on input ports
    #
    # @param ports [Array<Number>] array of port numbers
    # @return [String] group identifier
    # @api private
    def group_id(ports)
      if ports.nil? or ports.empty?
        return nil
      end

      unless ports.is_a? Set
        ports = Set.new(ports)
      end

      # Lolwut, #hash is inconsistent between ruby processes
      "Beaker-#{Zlib.crc32(ports.inspect)}"
    end

    # Return an existing group, or create new one
    #
    # @param region [AWS::EC2::Region] the AWS region control object
    # @param ports [Array<Number>] an array of port numbers
    # @return [AWS::EC2::SecurityGroup] created security group
    # @api private
    def ensure_group(region, ports)
      name = group_id(ports)

      group = region.security_groups.filter('group-name', name).first

      if group.nil?
        group = create_group(region, ports)
      end

      group
    end

    # Create a new security group
    #
    # @param region [AWS::EC2::Region] the AWS region control object
    # @param ports [Array<Number>] an array of port numbers
    # @return [AWS::EC2::SecurityGroup] created security group
    # @api private
    def create_group(region, ports)
      name = group_id(ports)
      group = region.security_groups.create(name,
                                            :description => "Custom Beaker security group for #{ports.to_a}")

      unless ports.is_a? Set
        ports = Set.new(ports)
      end

      ports.each do |port|
        group.authorize_ingress(:tcp, port)
      end

      group
    end

    # Return a hash containing the fog credentials for EC2
    #
    # @param dot_fog [String] dot fog path
    # @return [Hash<Symbol, String>] ec2 credentials
    # @api private
    def load_fog_credentials(dot_fog = '.fog')
      fog = YAML.load_file( dot_fog )

      default = fog[:default]

      creds = {}
      creds[:access_key] = default[:aws_access_key_id]
      creds[:secret_key] = default[:aws_secret_access_key]
      creds
    end
  end
end
