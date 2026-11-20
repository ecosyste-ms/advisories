require 'test_helper'
require_relative '../../script/patch_index/patch_similarity'

class PatchSimilarityTest < ActiveSupport::TestCase
  test 'normalization retains paths, signs and context as independent evidence' do
    diff = "--- a/code.rb\n+++ b/code.rb\n@@ -1,2 +1,2 @@\n context\n-old_value\n+new_value\n".b
    variants = [diff, 'Subject: update' + "\n" + diff.gsub('1,2', '8,2'), diff.sub('context', 'updated'),
      diff.gsub('code.rb', 'test.rb'), diff.gsub('-old_value', '-new_value').gsub('+new_value', '+old_value')]
    Dir.mktmpdir do |dir|
      ids = variants.map do |bytes|
        sha = Digest::SHA256.hexdigest(bytes)
        File.binwrite(File.join(dir, sha), bytes)
        sha
      end
      out = Pathname(dir).join('pairs.gz')
      PatchSimilarity.generate([dir], out)
      pairs = PatchIndex::Similarity.load_index(out)
      assert_equal({ 'same_hunks' => true, 'same_edits' => true }, pairs.fetch(ids[0]).fetch(ids[1]))
      assert_equal({ 'same_edits' => true }, pairs.fetch(ids[0]).fetch(ids[2]))
      refute pairs.key?(ids[3])
      refute pairs.key?(ids[4])
      File.binwrite(File.join(dir, ids.first), 'corrupt')
      assert_raises(IOError) { PatchSimilarity.generate([dir], out) }
      assert_equal pairs, PatchIndex::Similarity.load_index(out)
    end
  end

  test 'near-pair search includes the threshold and agrees with exhaustive comparisons' do
    random = Random.new(491)
    sets = 120.times.to_h { |i| [i, (0..16).to_a.sample(random.rand(4..14), random: random).to_set] }
    sets[120], sets[121] = (1..8).to_set, (1..10).to_set
    expected = sets.keys.combination(2).filter_map do |a, b|
      common = (sets[a] & sets[b]).size
      union = (sets[a] | sets[b]).size
      [[a, b], [common, union]] if common >= 6 && 5 * common >= 4 * union
    end.to_h
    actual = {}
    PatchSimilarity.near_pairs(sets) { |pair, overlap| actual[pair] = overlap }
    assert_equal expected, actual
    assert_equal [8, 10], actual[[120, 121]]
  end
end
