class Api::V1::PatchesController < Api::V1::ApplicationController
  rescue_from Purl::Error do |error|
    render json: { error: error.message }, status: :bad_request
  end

  def index
    matches = PatchOccurrence.matching(params.permit(:purl, :repository_url, :advisory, :distribution))
    @pagy, @patches = pagy(Patch.where(id: matches.select(:patch_id)).order(:id))
    load_occurrences(matches.where(patch_id: @patches.map(&:id)))
  end

  def show
    @patch = Patch.declared.find_by!(sha256: params[:sha256])
    load_occurrences(@patch.patch_occurrences)
  end

  def load_occurrences(scope)
    occurrences = scope.preload(:patch, :patch_release).order(:id).to_a
    @occurrences = occurrences.group_by(&:patch_id)
    @advisories = Patch.advisories_by_identifier(occurrences)
  end
end
