class Source < ApplicationRecord
  has_many :advisories

  def source_instance
    @source_instance ||= source_class.new(self)
  end

  def source_class
    Sources::Base.find(kind)
  end

  def sync_advsiories
    source_instance.list_advisories.each do |advisory|
      a = advisories.find_or_initialize_by(uuid: advisory[:uuid], first_patched_version: advisory[:first_patched_version])
      a.update(advisory)
    end
  end
end
