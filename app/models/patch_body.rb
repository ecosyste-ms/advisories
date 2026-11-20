class PatchBody < ApplicationRecord
  PREVIEW_BYTES = 64.kilobytes
  PREVIEW_LINES = 500

  def self.store!(sha256, bytes)
    # A binary parameter avoids hex-encoding large patches into the SQL statement.
    with_connection do |connection|
      connection.raw_connection.exec_params(
        'INSERT INTO patch_bodies (sha256, contents) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING',
        [sha256, { value: bytes, format: 1 }]
      )
    end
  end

  def self.preview(sha256)
    select("sha256, octet_length(contents) AS byte_size, substring(contents FROM 1 FOR #{PREVIEW_BYTES}) AS contents")
      .find_by(sha256: sha256)
  end

  def preview_lines
    @preview_lines ||= contents.dup.force_encoding('UTF-8').scrub.gsub(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/, "\uFFFD").each_line.take(PREVIEW_LINES + 1)
  end

  def truncated?
    byte_size > PREVIEW_BYTES || preview_lines.size > PREVIEW_LINES
  end
end
