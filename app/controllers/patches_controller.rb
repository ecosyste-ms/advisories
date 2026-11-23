class PatchesController < ApplicationController
  rescue_from Purl::Error do |error|
    render plain: error.message, status: :bad_request
  end

  def index
    @filters = params.permit(:purl, :repository_url, :advisory, :distribution).to_h.transform_values(&:strip).compact_blank
    @sort = Patch::INDEX_ORDERS.key?(params[:sort]) ? params[:sort] : 'newest'
    matches = PatchOccurrence.matching(@filters.symbolize_keys)
    @pagy, @patches = pagy(Patch.where(id: matches.select(:patch_id)).order(Patch::INDEX_ORDERS.fetch(@sort)), limit: 25)
    @occurrences = matches.where(patch_id: @patches.map(&:id)).preload(:patch_release).order(:id).group_by(&:patch_id)
  end

  def show
    @patch = Patch.declared.find_by!(sha256: params[:sha256])
    @body = PatchBody.preview(@patch.sha256)
    @occurrences = @patch.patch_occurrences.preload(:patch, :patch_release).order(:id).to_a
    @advisories = Patch.advisories_by_identifier(@occurrences)
  end

  def download
    patch = Patch.declared.find_by!(sha256: params[:sha256])
    send_data PatchBody.find(patch.sha256).contents, filename: "#{patch.sha256}.patch", type: 'application/octet-stream',
      disposition: 'attachment'
  end
end
