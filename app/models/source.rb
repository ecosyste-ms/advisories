class Source < ApplicationRecord
  has_many :advisories
  has_many :advisory_records

  validates :name, :kind, :url, presence: true

  def to_s
    name
  end

  def source_instance
    @source_instance ||= source_class.new(self)
  end

  def source_class
    Sources::Base.find(kind)
  end

  def sync_advisories
    with_sync_lock { source_instance.sync_advisories }
  end

  def with_sync_lock
    self.class.connection_pool.with_connection do |connection|
      key = connection.quote("source_import:#{id}")
      connection.execute("SELECT pg_advisory_lock(hashtextextended(#{key}, 0))")
      begin
        yield
      ensure
        connection.execute("SELECT pg_advisory_unlock(hashtextextended(#{key}, 0))")
      end
    end
  end

  ICONS = {
    'github' => 'github',
    'osv' => 'google',
    'erlef' => 'hexagon'
  }.freeze

  def icon
    ICONS[kind]
  end
end
