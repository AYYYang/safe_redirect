require 'spec_helper'
require 'stringio'
require 'logger'

module SafeRedirect
  describe SafeRedirect do
    class BaseController
      def redirect_to(*)
        # test stub
      end
    end

    class Controller < BaseController
      extend SafeRedirect
    end

    SAFE_PATHS = [
      'https://www.bukalapak.com',
      '/',
      '/foobar',
      'http://www.twitter.com',
      'http://blah.foo.org',
      'http://bl-ah.foo.org',
      'http://foo.org',
      'http://foo.org/',
      'http://bar.com/safe',
      'http://bar.com/safe/123',
      :back,
      ['some', 'object'],
      { controller: 'home', action: 'index' },
    ]

    UNSAFE_PATHS = [
      "https://www.bukalapak.com@google.com",
      "http://////@@@@@@attacker.com//evil.com",
      "//bukalapak.com%25%40%25%40%25%40%25%40%25%40%25%40%25%40evil.com",
      "evil.com",
      ".evil.com",
      "%@%@%@%@%@%@%@%@%@%@evil.com",
      "https://www-bukalapak.com",
      "https://www.bukalapak.com\n.evil.com",
      "http://blah.blah.foo.org",
      "///bit.ly/1hqE77G",
      "http://bar.com",
      'http://bar.com/unsafe',
      'http://bar.com/unsafe/123',
    ]

    shared_examples_for 'nonlocal hosts' do |klass|
      SAFE_PATHS.each do |path|
        it "considers #{path} a safe path" do
          expect(klass.safe_path(path)).to eq(path)
        end
      end

      UNSAFE_PATHS.each do |path|
        it "considers #{path} an unsafe path" do
          expect(klass.safe_path(path)).to eq(SafeRedirect.configuration.default_path)
        end
      end

      it 'filters host, port, and protocol options when hash is passed to safe_path' do
        hash = { host: 'yahoo.com', port: 80, protocol: 'https', controller: 'home', action: 'index' }
        safe_hash = { port: 80, protocol: 'https', controller: 'home', action: 'index' }
        expect(klass.safe_path(hash)).to eq(safe_hash)
      end

      it 'can use redirect_to method with only the target path' do
        klass.redirect_to '/'
      end

      it 'can use redirect_to method with both the target path and the options' do
        klass.redirect_to '/', notice: 'Back to home page'
      end

      it 'can log violations' do
        log_io = StringIO.new
        SafeRedirect.configure{ |config| config.log = Logger.new(log_io) }

        klass.redirect_to(UNSAFE_PATHS.first)

        expect(log_io.size).not_to eq(0)
      end
    end

    context 'whitelist_local is not set' do

      before(:all) do
        load_config
      end

      it_should_behave_like 'nonlocal hosts', Controller

      it 'considers local addresses as unsafe' do
        path = 'http://127.0.0.1'
        expect(Controller.safe_path(path)).to eq(SafeRedirect.configuration.default_path)
      end
    end

    context 'whitelist_local is set' do
      before(:all) do
        load_config true
      end

      it_should_behave_like 'nonlocal hosts', Controller

      it 'considers local addresses as safe' do
        path = 'http://127.0.0.1'
        expect(Controller.safe_path(path)).to eq(path)
      end
    end

    context 'calling module methods directly and whitelist_local is not set' do
      before :all do
        load_config
      end

      it_should_behave_like 'nonlocal hosts', SafeRedirect
    end


    context "forcing HTTPS" do
      before do
        reset_config
        load_config
        allow(SafeRedirect.configuration).to receive(:force_https).and_return(true)
        allow(SafeRedirect.configuration).to receive(:force_https).and_return(true)
      end

      HTTPS_SAFE_PATHS = [
        'https://www.twitter.com',
        'https://www.twitter.com/',
        'https://www.twitter.com/123',
        'https://bl-ah.foo.org',
        'https://bl-ah.foo.org/',
        'https://bl-ah.foo.org/query?param=123',
        'https://foo.org',
        'https://foo.org/query?param=123',
        'https://bar.com/safe',
        'https://bar.com/safe/123',
      ]

      HTTPS_UNSAFE_PATHS = [
        '.twitter.com',
        'twitter.com',
        'www.twitter.com',
        'http://www.twitter.com',
        'http://www.twitter.com/',
        'http://www.twitter.com/123',
        '//bl-ah.foo.org',
        '/',
        'http://blah.foo.org',
        'http://bl-ah.foo.org',
        'http://foo.org',
        'http://foo.org/',
        'http://bar.com/safe',
        'http://bar.com/safe/123',
      ]

      HTTPS_SAFE_PATHS.each do |path|
        it "considers #{path} a safe path" do
          expect(Controller.safe_path(path)).to eq(path)
        end
      end

      HTTPS_UNSAFE_PATHS.each do |path|
        it "considers #{path} an unsafe path" do
          expect(Controller.safe_path(path)).to eq(SafeRedirect.configuration.default_path)
        end
      end
    end
  end
end
