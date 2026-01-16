class Api::V1::SourcesController < Api::V1::ApplicationController
  def index
    @sources = Source.all.order(:name)
  end

  def show
    @source = Source.find_by!(kind: params[:id])
  end
end
