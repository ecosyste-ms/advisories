class PatchesController < ApplicationController
  rescue_from Purl::Error, PatchOccurrence::InvalidRange do |error|
    render plain: error.message, status: :bad_request
  end

  def index
    filters = params.permit(:purl, :distribution)
    @purl = filters[:purl].presence
    @distribution = filters[:distribution].to_s.strip.downcase.presence
    @distributions = PatchRelease.distinct.pluck(:distribution).map(&:downcase).uniq.sort
    matches = PatchOccurrence.matching(distribution: @distribution, purl: @purl)
    @sort = Patch::INDEX_ORDERS.key?(params[:sort]) ? params[:sort] : 'newest'
    @pagy, page = pagy(Patch.where(id: matches.select(:patch_id)), limit: 25)
    @patches = page.left_joins(:patch_body).select('patches.*, octet_length(patch_bodies.contents) AS byte_size')
      .order(Arel.sql(Patch::INDEX_ORDERS.fetch(@sort)))
    @occurrences = matches.where(patch_id: @patches.map(&:id)).preload(:patch_release).group_by(&:patch_id)
  end

  def compare
    left, right = params.values_at(:sha256, :other_sha256)
    @evidence = PatchIndex::Similarity.index.dig(left, right)
    raise ActiveRecord::RecordNotFound unless @evidence

    patches = Patch.declared.preload(:patch_body, patch_occurrences: :patch_release)
    @left = patches.find_by!(sha256: left)
    @right = patches.find_by!(sha256: right)
    if @left.patch_body && @right.patch_body
      @lines = PatchIndex::Comparison.lines(@left.patch_body.contents, @right.patch_body.contents)
    end
  end

  def download
    patch = Patch.declared.find_by!(sha256: params[:sha256])
    body = PatchBody.find(patch.sha256)
    send_data body.contents, filename: "#{patch.sha256}.patch", type: 'application/octet-stream', disposition: 'attachment'
  end

  def show
    @patch = Patch.declared.preload(patch_occurrences: :patch_release).find_by!(sha256: params[:sha256])
    @body = PatchBody.preview(@patch.sha256)
    @occurrences = @patch.patch_occurrences.sort_by(&:id)
    @advisories = Patch.advisories_by_identifier(@occurrences)
    keys = @occurrences.map { |o| [o.patch_release.distribution, o.patch_release.package_name] }
    @packages = Package.indexed_by_identity(keys + @occurrences.filter_map(&:upstream_package_key))
    @similar = PatchIndex::Similarity.for_patch(@patch)
    @observations = @patch.debian_observations(@occurrences)
  end
end
