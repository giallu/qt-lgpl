# Included right after project() of selected third-party CMake projects
# (CMAKE_PROJECT_<name>_INCLUDE) to build them without unity build.
# litehtml (used by qttools' Assistant) defines macros such as
# "#define in /" in its headers, which break other sources once they are
# merged into one translation unit.
set(CMAKE_UNITY_BUILD OFF)
