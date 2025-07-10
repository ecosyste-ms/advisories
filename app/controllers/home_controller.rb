class HomeController < ApplicationController
  def index
    @recent_advisories = Advisory.order(published_at: :desc).limit(4)
  end
end