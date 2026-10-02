class Api::V1::SourcesController < Api::V1::ApplicationController
  def index
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @sources = Source.all.order(:name)
  end

  def show
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @source = Source.find_by!(kind: params[:id])
  end
end
