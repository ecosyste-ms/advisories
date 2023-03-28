class Source < ApplicationRecord
  has_many :advisories

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
    source_instance.list_advisories.each do |advisory|
      a = advisories.find_or_initialize_by(uuid: advisory[:uuid])
      a.update!(advisory)
    end
  end
end
