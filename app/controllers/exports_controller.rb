class ExportsController < ApplicationController
  def index
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @exports = Export.order("date DESC")
  end
end