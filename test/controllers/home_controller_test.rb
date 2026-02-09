require 'test_helper'

class HomeControllerTest < ActionDispatch::IntegrationTest
  test 'renders home page' do
    get '/'
    assert_response :success
    assert_template 'home/index'
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test 'assigns recent advisories' do
    get '/'
    assert_not_nil assigns(:recent_advisories)
    assert_equal 4, assigns(:recent_advisories).limit_value
  end
end