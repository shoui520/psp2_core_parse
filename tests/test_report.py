from psp2_core_parse.report import ANALYSIS_BANNER


def test_exception_analysis_banner_is_exact():
    assert ANALYSIS_BANNER == """*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************"""
