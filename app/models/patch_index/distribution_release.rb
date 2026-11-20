module PatchIndex
  class DistributionRelease
    def initialize(directory)
      @directory = directory
    end

    def import(release)
      distribution = release.fetch('source').downcase
      raise ArgumentError, 'unsupported distribution' unless %w[fedora ubuntu].include?(distribution)
      version = release.fetch('version')
      url = release.fetch('url')
      entries = release.fetch('declarations').map do |row|
        member = row.fetch('name')
        sha = row.fetch('sha256')
        raise ArgumentError, 'invalid member digest' unless sha.match?(/\A[0-9a-f]{64}\z/)
        bytes = @directory.join('blobs', sha).binread
        options = row['options']
        strip = if distribution == 'ubuntu'
          options.empty? ? 1 : options.sole[/\A-p(\d+)\z/, 1]&.to_i if options.size <= 1
        end
        document = Document.new(bytes, strip: strip)
        raise IOError, "patch checksum mismatch for #{member}" unless document.sha256 == sha
        metadata = row.except('name', 'sha256').merge('member' => member, 'archive_sha256' => release.fetch('sha256'))
        document.entry(name: member.delete_prefix('debian/patches/'), source_url: url, declaration: metadata)
      end
      identity = { distribution: distribution, package_name: release.fetch('package'), version: version, revision: version.rpartition('-').last }
      PatchRelease.record!(identity, source_url: url, metadata: release.slice('suite', 'sha256'),
        component: { 'reason' => 'upstream identity has not been assessed' }, entries: entries)
    end
  end
end
