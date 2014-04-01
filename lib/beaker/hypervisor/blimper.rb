require 'blimpy'
require 'yaml' unless defined?(YAML)

module Beaker
  class Blimper < Beaker::Hypervisor

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

    def initialize(blimpy_hosts, options)
      @options = options
      @logger = options[:logger]
      @hosts = blimpy_hosts
      @blimpy = Blimpy
    end

    def provision
      ami_spec= YAML.load_file(@options[:ec2_yaml])["AMI"]

      fleet = @blimpy.fleet do |fleet|
        @hosts.each do |host|
          amitype = host['vmname'] || host['platform']
          amisize = host['amisize'] || 'm1.small'
          #use snapshot provided for this host
          image_type = host['snapshot']
          if not image_type
            raise "No snapshot/image_type provided for blimpy provisioning"
          end
          ami = ami_spec[amitype]
          fleet.add(:aws) do |ship|
            ship.name = host.name
            ship.ports = amiports(host)
            ship.image_id = ami[:image][image_type.to_sym]
            if not ship.image_id
              raise "No image_id found for host #{ship.name} (#{amitype}:#{amisize}) using snapshot/image_type #{image_type}"
            end
            ship.flavor = amisize
            ship.region = ami[:region]
            ship.username = 'root'
            ship.tags = {
              :department => @options[:department],
              :project => @options[:project],
              :jenkins_build_url => @options[:jenkins_build_url],
            }
          end
          @logger.debug "Added #{host.name} (#{amitype}:#{amisize}) using snapshot/image_type #{image_type} to blimpy fleet"
        end
      end

      # Attempt to start the fleet, we wrap it with some error handling that
      # deals with generic Fog errors and retrying in case these errors are
      # transient.
      fleet_retries = 0
      begin
        @logger.notify("\nblimpy: Calling fleet.start")
        fleet.start
      rescue Fog::Errors::Error, SystemCallError => ex
        @logger.notify("\nblimpy: Exception raised calling fleet.start: \#<#{ex.class.to_s}: #{ex.message}>")
        fleet_retries += 1
        if fleet_retries <= 10
          @logger.notify("\nblimpy: Retrying due to failure. Current retry attempt is #{fleet_retries}.")

          # Provide some expanding back-off with some randomization
          sleep_time = 1
          fleet_retries.times { sleep_time = sleep_time * (1.8+(rand(200)/1000.0)) }
          @logger.notify("\nblimpy: Sleeping #{sleep_time} seconds before calling fleet.destroy to cleanup before retrying fleet.start.")
          sleep sleep_time

          destroy_retries = 0
          begin
            @logger.notify("\nblimpy: Calling fleet.destroy")
            timeout(300) do
              fleet.destroy
            end
          rescue Fog::Compute::AWS::Error => ex
            @logger.notify("\nblimpy: Exception calling fleet.destroy: \#<#{ex.class.to_s}: #{ex.message}>")
            destroy_retries += 1
            if destroy_retries <= 10
              @logger.notify("\nblimpy: Retrying fleet.destroy due to failure. Current retry attempt is #{destroy_retries}.")

              # Provide some expanding back-off with some randomization
              sleep_time = 10
              destroy_retries.times { sleep_time = sleep_time * (1.8+(rand(200)/1000.0)) }
              @logger.notify("\nblimpy: Sleeping #{sleep_time} seconds before retrying fleet.destroy.")
              sleep sleep_time

              retry
            else
              raise ex
            end
          rescue => ex
            @logger.notify("\nblimpy: Exception calling fleet.destroy: \#<#{ex.class.to_s}: #{ex.message}>")
          end

          # Provide some expanding back-off with some randomization
          sleep_time = 10
          fleet_retries.times { sleep_time = sleep_time * (1.8+(rand(200)/1000.0)) }
          @logger.notify("\nblimpy: Sleeping #{sleep_time} seconds before retrying fleet.start.")
          sleep sleep_time

          retry
        else
          @logger.error("\nblimpy: Retried Fog #{fleet_retries} times, giving up.")

          destroy_retries = 0
          begin
            @logger.notify("\nblimpy: Calling fleet.destroy")
            timeout(300) do
              fleet.destroy
            end
          rescue Fog::Compute::AWS::Error => ex
            @logger.notify("\nblimpy: Exception calling fleet.destroy: \#<#{ex.class.to_s}: #{ex.message}>")
            destroy_retries += 1
            if destroy_retries <= 10
              @logger.notify("\nblimpy: Retrying fleet.destroy due to failure. Current retry attempt is #{destroy_retries}.")

              # Provide some expanding back-off with some randomization
              sleep_time = 10
              destroy_retries.times { sleep_time = sleep_time * (1.8+(rand(200)/1000.0)) }
              @logger.notify("\nblimpy: Sleeping #{sleep_time} seconds before retrying fleet.destroy.")
              sleep sleep_time

              retry
            else
              raise ex
            end
          rescue => ex
            @logger.notify("\nblimpy: Exception calling fleet.destroy: \#<#{ex.class.to_s}: #{ex.message}>")
          end
          @logger.notify("\nblimpy: Throwing exception")
          raise ex
        end
      end

      # Configure our nodes to match the blimp fleet
      # Also generate hosts entries for the fleet, since we're iterating
      etc_hosts = "127.0.0.1\tlocalhost localhost.localdomain\n"
      fleet.ships.each do |ship|
        ship.wait_for_sshd
        name = ship.name
        host = @hosts.select { |host| host.name == name }[0]
        host['ip'] = ship.dns
        host.exec(Command.new("hostname #{name}"))
        ip = get_ip(host) 
        domain = get_domain_name(host)
        etc_hosts += "#{ip}\t#{name}\t#{name}.#{domain}\n"
      end

      # Send our hosts information to the nodes
      @hosts.each do |host|
        set_etc_hosts(host, etc_hosts)
      end

    end #revert_blimpy

    def cleanup
      fleet = @blimpy.fleet do |fleet|
        @hosts.each do |host|
          fleet.add(:aws) do |ship|
            ship.name = host.name
          end
        end
      end

      @logger.notify "Destroying Blimpy boxes"
      fleet.destroy
    end

  end
end
