require 'rubygems'
require 'rspec'

require File.join(File.dirname(__FILE__), '..', 'lib', 'safe_redirect')

def reset_config
  SafeRedirect.reset_config
end

def load_config(whitelist_local = false, force_https = false)
  SafeRedirect.configure do |config|
    config.default_path = '/sdsdkkk'
    config.domain_whitelists = %w{www.twitter.com www.bukalapak.com *.foo.org}
    config.whitelist_local = whitelist_local
    config.force_https = force_https
  end
end

module SafeRedirect
  class << self
    def reset_config
      @configuration = Configuration.new
    end
  end
end