require 'test_helper'

class CacheHeadersTest < ActionDispatch::IntegrationTest
  test 'html pages do not set cookies' do
    get '/'
    assert_response :success
    assert_nil response.headers['Set-Cookie']
  end

  test 'advisory show does not set cookies' do
    advisory = create(:advisory)
    get advisory_path(advisory)
    assert_response :success
    assert_nil response.headers['Set-Cookie']
  end

  test 'api endpoints do not set cookies' do
    get api_v1_advisories_path(format: :json)
    assert_response :success
    assert_nil response.headers['Set-Cookie']
  end
end
