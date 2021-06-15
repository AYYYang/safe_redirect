require 'rubygems'
require 'rspec'

require File.join(File.dirname(__FILE__), '..', 'lib', 'safe_redirect')

def reset_config
  SafeRedirect.reset_config
end

def load_config(whitelist_local = false)
  SafeRedirect.configure do |config|
    config.default_path = '/sdsdkkk'
    config.domain_whitelists = %w{www.twitter.com www.bukalapak.com *.foo.org *bar.com/safe}
    config.whitelist_local = whitelist_local
  end
end

module SafeRedirect
  class << self
    def reset_config
      @configuration = Configuration.new
    end
  end
end