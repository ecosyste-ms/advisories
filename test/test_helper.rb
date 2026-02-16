ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

require 'webmock/minitest'
require 'mocha/minitest'
require 'sidekiq/testing'

# Disable unique jobs in tests to avoid lock conflicts
Sidekiq::Testing.inline!
SidekiqUniqueJobs.configure do |config|
  config.enabled = false
end

class ActiveSupport::TestCase
  include FactoryBot::Syntax::Methods
  Shoulda::Matchers.configure do |config|
    config.integrate do |with|
      with.test_framework :minitest
      with.library :rails
    end
  end

  setup do
    stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/packages/lookup})
      .to_return(status: 200, body: [].to_json, headers: { 'Content-Type' => 'application/json' })
  end
end
