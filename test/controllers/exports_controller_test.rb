require 'test_helper'

class ExportsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @export = Export.create!(date: '2019-01-01', bucket_name: 'test-bucket', advisories_count: 123)
  end

  test 'renders index' do
    get exports_path
    assert_response :success
    assert_template 'exports/index'
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end
end