class HomeController < ApplicationController
  def index
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @recent_advisories = Advisory.order(published_at: :desc).limit(4)
  end
end