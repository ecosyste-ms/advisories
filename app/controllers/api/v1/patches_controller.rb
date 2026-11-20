class Api::V1::PatchesController < Api::V1::ApplicationController
  rescue_from Purl::Error, PatchOccurrence::InvalidRange do |error|
    render json: { error: error.message }, status: :bad_request
  end

  def index
    matches = PatchOccurrence.matching(params.permit(:purl, :distribution, :advisory, :version_range))
    @pagy, @patches = pagy(Patch.where(id: matches.select(:patch_id)).order(:id))
    load_occurrences(matches.where(patch_id: @patches.map(&:id)))
  end

  def show
    @patch = Patch.joins(:patch_occurrences).find(params[:id])
    load_occurrences(@patch.patch_occurrences)
  end

  def load_occurrences(scope)
    occurrences = scope.preload(:patch_release, :patch).order(:id).to_a
    @occurrences = occurrences.group_by(&:patch_id)
    digests = @occurrences.values.map { |group| group.first.patch.sha256 }
    @downloadable = PatchBody.where(sha256: digests).pluck(:sha256).to_set
    @advisories = Patch.advisories_by_identifier(occurrences)
  end
end
