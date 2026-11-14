from prompt_ids.preprocess.normalizer import (
    Normalizer,
    fold_spacing,
    reglue_spaced,
    strip_invisible,
)


def test_zero_width_removed():
    assert strip_invisible("Ig\u200bnore me") == "Ignore me"


def test_combining_mark_removed():
    assert "i\u0301gnore" not in strip_invisible("i\u0301gnore")


def test_homoglyph_mapped():
    # 西里尔 а/с/е 替换拉丁 a/c/e
    assert Normalizer().canonical("аdmin pаssword") == "admin password"


def test_fullwidth_normalized():
    assert Normalizer().canonical("ＩＧＮＯＲＥ") == "IGNORE"


def test_reglue_single_chars():
    assert reglue_spaced("i g n o r e all previous") == "ignore all previous"


def test_reglue_keeps_words():
    assert reglue_spaced("please ignore everything") == "please ignore everything"


def test_fold_spacing_strips_all():
    assert fold_spacing("i g.n-o_r e") == "ignore"


def test_variants_unique_and_first_is_original():
    out = Normalizer().variants("Hello   world")
    assert out[0] == "Hello world"
    assert len(out) == len(set(out))
