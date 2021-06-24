#include <algorithm>
#include <chrono>
#include <execution>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>

#include "cmdline.h"


namespace fs = std::filesystem;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;


using PathSize = std::pair<fs::path, uint64_t>;
using PathSizeIdx = std::pair<uint64_t, size_t>;
using PathVec  = std::vector<fs::path>;
using IndexVec = std::vector<size_t>;
using PathSizeIdxVec = std::vector<PathSizeIdx>;

using DuplicateFilesNames = std::unordered_map<std::string, IndexVec>;
using DuplicateFilesSizes = std::unordered_map<uint64_t, uint32_t>;
using DuplicateFilesHash  = std::unordered_map<uint64_t, uint32_t>;

using MemBuffer512  = std::array<char, 512>;
using FileMemBuffer = std::vector<std::byte>;
using SHA2Hash      = std::array<uint8_t, 32>;

static std::string ALL_FILES("*.*");

namespace
{
    struct PathDetails
    {
        fs::path m_path{};
        uint64_t m_size{};
    };

    struct NameBasedGroup
    {
        IndexVec m_duplicates{};
        uint64_t m_totalSize{0U};
    };
}

using PathDetailsVec = std::vector<PathDetails>;
using NameBasedGroupVec = std::vector<NameBasedGroup>;

// https://raw.githubusercontent.com/p-ranav/glob/master/single_include/glob/glob.hpp
namespace
{
    static inline bool string_replace(std::string& str, const std::string& from, const std::string& to)
    {
        std::size_t start_pos = str.find(from);
        if (start_pos == std::string::npos)
            return false;
        str.replace(start_pos, from.length(), to);
        return true;
    }

    static inline std::string translate(const std::string & pattern)
    {
        std::size_t i = 0, n = pattern.size();
        std::string result_string;

        while (i < n)
        {
            auto c = pattern[i];
            i += 1;
            if (c == '*')
            {
                result_string += ".*";
            }
            else if (c == '?')
            {
                result_string += ".";
            }
            else if (c == '[')
            {
                auto j = i;

                if (j < n && pattern[j] == '!')
                    j += 1;

                if (j < n && pattern[j] == ']')
                    j += 1;

                while (j < n && pattern[j] != ']')
                    j += 1;

                if (j >= n)
                {
                    result_string += "\\[";
                }
                else
                {
                    auto stuff = std::string(pattern.begin() + i, pattern.begin() + j);
                    if (stuff.find("--") == std::string::npos)
                    {
                        string_replace(stuff, std::string{ "\\" }, std::string{ R"(\\)" });
                    }
                    else
                    {
                        std::vector<std::string> chunks;
                        std::size_t k = 0;
                        if (pattern[i] == '!')
                            k = i + 2;
                        else
                            k = i + 1;

                        while (true)
                        {
                            k = pattern.find("-", k, j);
                            if (k == std::string::npos)
                                break;

                            chunks.push_back(std::string(pattern.begin() + i, pattern.begin() + k));
                            i = k + 1;
                            k = k + 3;
                        }

                        chunks.push_back(std::string(pattern.begin() + i, pattern.begin() + j));
                        // Escape backslashes and hyphens for set difference (--).
                        // Hyphens that create ranges shouldn't be escaped.
                        bool first = false;
                        for (auto& s : chunks)
                        {
                            string_replace(s, std::string{ "\\" }, std::string{ R"(\\)" });
                            string_replace(s, std::string{ "-" }, std::string{ R"(\-)" });
                            if (first)
                            {
                                stuff += s;
                                first = false;
                            }
                            else
                            {
                                stuff += "-" + s;
                            }
                        }
                    }

                    // Escape set operations (&&, ~~ and ||).
                    std::string result;
                    std::regex_replace(std::back_inserter(result),          // result
                        stuff.begin(), stuff.end(),          // string
                        std::regex(std::string{ R"([&~|])" }), // pattern
                        std::string{ R"(\\\1)" });             // repl
                    stuff = result;
                    i = j + 1;

                    if (stuff[0] == '!')
                        stuff = "^" + std::string(stuff.begin() + 1, stuff.end());
                    else if (stuff[0] == '^' || stuff[0] == '[')
                        stuff = "\\\\" + stuff;

                    result_string = result_string + "[" + stuff + "]";
                }
            }
            else
            {
                // SPECIAL_CHARS
                // closing ')', '}' and ']'
                // '-' (a range in character set)
                // '&', '~', (extended character set operations)
                // '#' (comment) and WHITESPACE (ignored) in verbose mode
                static std::string special_characters = "()[]{}?*+-|^$\\.&~# \t\n\r\v\f";
                static std::map<int, std::string> special_characters_map;
                if (special_characters_map.empty())
                {
                    for (auto& c : special_characters)
                    {
                        special_characters_map.insert(
                            std::make_pair(static_cast<int>(c), std::string{ "\\" } +std::string(1, c)));
                    }
                }

                if (special_characters.find(c) != std::string::npos)
                    result_string += special_characters_map[static_cast<int>(c)];
                else
                    result_string += c;

            }
        }
        return std::string{ "((" } +result_string + std::string{ R"()|[\r\n])$)" };
    }

    static inline std::regex compile_pattern(const std::string & pattern)
    {
        return std::regex(pattern, std::regex::ECMAScript | std::regex::icase);
    }

    static inline bool fnmatch_case(const fs::path & name, const std::regex & pattern)
    {
        bool res = false;
        try
        {
            res = std::regex_match(name.string(), pattern);
        }
        catch (std::exception&)
        {
            res = false;
        }
        return res;
    }

    static inline bool fnmatch_case(const fs::path& name, const std::string & pattern)
    {
        return std::regex_match(name.string(), compile_pattern(pattern));
    }

    static inline PathVec filter(const PathVec & names, const std::regex & pattern)
    {
        // std::cout << "Pattern: " << pattern << "\n";
        PathVec result;
        for (auto& name : names)
        {
            // std::cout << "Checking for " << name.string() << "\n";
            if (fnmatch_case(name, pattern))
                result.push_back(name);

        }
        return result;
    }
}



//--------------------------------------------------------------------------------------------
struct Options
{
    enum class Method
    {
        Name,
        NameSize,
        NameSizeContent
    };

    std::string Directory{};
    std::string Pattern{};
    std::string SkipPattern{};
    Method GroupingMethod{ Method::NameSize};
    bool Verbose{ false };
    bool NoBanner{ false };

    static Options WithDefaults()
    {
        Options opts{};

        opts.Directory = ".";
        opts.Pattern = "*";
        opts.GroupingMethod = Method::NameSize;

        return opts;
    }

    static Method FromString(const std::string& str)
    {
        if (str == "n")
            return Method::Name;
        else if (str == "ns")
            return Method::NameSize;
        else if (str == "nsc")
            return Method::NameSizeContent;
        else
            return Method::NameSize;
    }

private:
    Options() = default;
};


//--------------------------------------------------------------------------------------------
static Options getCmdOptions(int argc, char* argv[])
{
    cmdline::parser cmdParser;

    cmdParser.set_program_name("lsdups.exe");

    std::string DEFAULT_STRING_VALUE("");
    bool MANDATORY_ARG = true;
    bool OPTIONAL_ARG = false;
    bool DEFAULT_BOOL_VALUE_TRUE = true;
    bool DEFAULT_BOOL_VALUE_FALSE = false;

    cmdParser.add<std::string>("dir", 'd',     "directory to analyze (defaults to current directory)", OPTIONAL_ARG, DEFAULT_STRING_VALUE);
    cmdParser.add<std::string>("pattern", 'p', "pattern for files to find (defaults to *.*)", OPTIONAL_ARG, "*.*");
    cmdParser.add<std::string>("skip", '\0',   "pattern for files to skip", OPTIONAL_ARG, DEFAULT_STRING_VALUE);

    // Boolean flags also can be defined.
    // Call add method without a type parameter.
    // cmdParser.add("name", '\0', "check name based duplicates");
    cmdParser.add<std::string>("method", '\0',
        R"(method to group and analyze possible duplicates (not used). 
             n   --> group only by name
             ns  --> group by name and then by size
             nsc --> group by name, size and then contents check)",
        OPTIONAL_ARG, "ns");

    cmdParser.add("verbose", 'v', "debug prints");
    cmdParser.add("nobanner", '\0', "Suppresses banner printing (off by default)");

    // Run parser.
    // It returns only if command line arguments are valid.
    // If arguments are invalid, a parser output error msgs then exit program.
    // If help flag ('--help' or '-?') is specified, a parser output usage message then exit program.
    cmdParser.parse_check(argc, argv);

    Options opts = Options::WithDefaults();

    if (cmdParser.exist("dir"))
        opts.Directory = cmdParser.get<std::string>("dir");
    if (cmdParser.exist("pattern"))
        opts.Pattern = cmdParser.get<std::string>("pattern");
    if (cmdParser.exist("skip"))
        opts.SkipPattern = cmdParser.get<std::string>("skip");
    if (cmdParser.exist("method"))
        opts.GroupingMethod = Options::FromString(cmdParser.get<std::string>("method"));

    opts.Verbose = cmdParser.exist("verbose");
    opts.NoBanner = cmdParser.exist("nobanner");

    return opts;
}

//-------------------------------------------------------------------------------------------------------
namespace
{
    struct Stats
    {
        size_t numFiles{};
        size_t numDirs{};
        long long timeMilliSecs{};
    };
}

//-------------------------------------------------------------------------------------------------------
static PathDetailsVec getAllMatchingFiles(const std::string& directoryPath, const std::string& pattern, 
                                          const std::string& skipPattern, bool verbose,
                                          Stats& travStats)
{
    using rdir_iter = fs::recursive_directory_iterator;
    using dir_entry = fs::directory_entry;

    auto t1 = high_resolution_clock::now();
    PathDetailsVec allFiles{};
    allFiles.reserve(100);

    std::string tweakedPattern = translate(pattern);
    const auto regex = compile_pattern(tweakedPattern);

    bool hasSkipPattern = !skipPattern.empty();
    std::regex skipRegex{};
    std::string tweakedSkipPattern{};

    if (hasSkipPattern)
    {
        tweakedSkipPattern = translate(skipPattern);
        skipRegex = compile_pattern(tweakedSkipPattern);
    }

    if (verbose)
    {
        std::cout << "Input Pattern: " << pattern << std::endl;
        std::cout << "Xlate Pattern: " << tweakedPattern << std::endl;

        std::cout << "Skip Pattern:  " << skipPattern << std::endl;
        std::cout << "Xlate Pattern: " << tweakedSkipPattern << std::endl;
    }
    
    for (const dir_entry& dirEntry : rdir_iter(directoryPath, fs::directory_options::skip_permission_denied))
    {
        try
        {
            if (dirEntry.is_regular_file())
            {
                ++travStats.numFiles;

                const fs::path& path = dirEntry.path().filename();
                if (fnmatch_case(path, regex))
                {
                    if(!hasSkipPattern || !fnmatch_case(path, skipRegex))
                        allFiles.emplace_back(PathDetails{ dirEntry, dirEntry.file_size()});
                }
            }
            else if (dirEntry.is_directory())
            {
                ++travStats.numDirs;
            }
        }
        catch (std::exception&)
        {
        }
    }
    auto t2 = high_resolution_clock::now();
    travStats.timeMilliSecs = duration_cast<milliseconds>(t2 - t1).count();

    return allFiles;
}

//-------------------------------------------------------------------------------------------------------
static void getAllFiles_r(const fs::directory_entry& dir, const std::regex& pattern, PathDetailsVec& output)
{
    for (const fs::directory_entry& e : fs::directory_iterator(dir))
    {
        if (e.is_directory())
        {
            getAllFiles_r(e, pattern, output);
        }
        else if (e.is_regular_file())
        {
            if (fnmatch_case(e.path(), pattern))
            {
                output.emplace_back(PathDetails{ e, e.file_size() });
            }
        }
    }
}

//-------------------------------------------------------------------------------------------------------
static PathDetailsVec getAllFiles_2(const std::string& directoryPath, const std::string& patternStr, long long& timeMilliSec)
{
    auto t1 = high_resolution_clock::now();
    PathDetailsVec allFiles{};
    allFiles.reserve(100);

    const auto regex = compile_pattern(patternStr);
    fs::directory_entry dirEnt{ fs::path(directoryPath) };
    getAllFiles_r(dirEnt, regex, allFiles);
    auto t2 = high_resolution_clock::now();
    timeMilliSec = duration_cast<milliseconds>(t2 - t1).count();

    return allFiles;
}

//-------------------------------------------------------------------------------------------------------
static void addFileNameToMapping(const PathDetails& path, size_t idx, DuplicateFilesNames& fnMapping)
{
    fs::path leafPath = path.m_path.filename();
    std::string fileName(leafPath.c_str());

    auto iter = fnMapping.find(fileName);
    if (iter == fnMapping.end())
        iter = fnMapping.insert(std::make_pair(fileName, IndexVec{})).first;

    iter->second.emplace_back(idx);
}

//-------------------------------------------------------------------------------------------------------
static uint64_t getTotalSize(const IndexVec& indices, const PathDetailsVec& allFiles)
{
    uint64_t totalSize = 0U;

    for (const auto& idx : indices)
        totalSize += allFiles[idx].m_size;

    return totalSize;
}


//-------------------------------------------------------------------------------------------------------
static std::vector<PathSizeIdxVec> splitBasedOnSize(PathSizeIdxVec input)
{
    std::sort(std::begin(input), std::end(input), 
        [](const PathSizeIdx& one, const PathSizeIdx& two)
        {
            return one.first < two.first;
        });

    std::vector<PathSizeIdxVec> splits{};

    size_t cStart = 0, idx = 0;
    for (; idx < input.size(); ++idx)
    {
        if (input[cStart].first == input[idx].first)
            continue;

        splits.emplace_back(&input[cStart], &input[idx]);
        cStart = idx;
    }

    splits.emplace_back(std::begin(input) + cStart, std::end(input));

    return splits;
}

//-------------------------------------------------------------------------------------------------------
static NameBasedGroupVec filterAndGroupFiles(const PathDetailsVec& allFiles, long long& timeMilliSec)
{
    auto t1 = high_resolution_clock::now();
    DuplicateFilesNames fnMapping{};

    for (size_t idx = 0; idx < allFiles.size(); ++idx)
    {
        const PathDetails& pd = allFiles[idx];
        addFileNameToMapping(pd, idx, fnMapping);
    }

    NameBasedGroupVec grouping{};
    grouping.reserve(fnMapping.size());

    for (const auto& data : fnMapping)
    {
        if (data.second.size() > 1)
        {
            PathSizeIdxVec fileSizes{};
            for (const auto& idx : data.second)
                fileSizes.emplace_back(std::make_pair(allFiles[idx].m_size, idx));

            std::vector<PathSizeIdxVec> splitPaths = splitBasedOnSize(fileSizes);

            for (const PathSizeIdxVec& el : splitPaths)
            {
                if (el.size() > 1)
                {
                    IndexVec idxVec{};
                    for (const auto& si : el)
                        idxVec.emplace_back(si.second);

                    grouping.emplace_back(NameBasedGroup{ idxVec,  getTotalSize(idxVec, allFiles) });
                }
            }
        }
    }

    std::sort(std::begin(grouping), std::end(grouping),
        [](const NameBasedGroup& first, const NameBasedGroup& second) -> bool
        {
            return first.m_totalSize > second.m_totalSize;
        });
    
    auto t2 = high_resolution_clock::now();
    timeMilliSec = duration_cast<milliseconds>(t2 - t1).count();
    return grouping;
}

//-------------------------------------------------------------------------------------------------------
static double toMB(uint64_t sizeInBytes)
{
    return sizeInBytes / 1024.0 / 1024.0;
}

//-------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    Options opts = getCmdOptions(argc, argv);

    if (!opts.NoBanner)
    {
        std::cout << std::endl;
        std::cout << "Author: Sarang Baheti, c 2021" << std::endl;
        std::cout << R"(Source: https://github.com/sarangbaheti/lsdups)" << std::endl;
        std::cout << R"(usage:)" << std::endl;
        std::cout << R"(   lsdups -d <dir> -p *asdf*.txt)" << std::endl << std::endl;
    }

    Stats travStas{};
    PathDetailsVec allFiles = getAllMatchingFiles(opts.Directory, opts.Pattern, opts.SkipPattern, opts.Verbose, travStas);
    std::cout << "Found " << allFiles.size() << " matching files" << std::endl;
    std::cout << "(FilesTraversed: " << travStas.numFiles
              << ", DirsTraversed: " << travStas.numDirs
              << " in " << travStas.timeMilliSecs << " milli-seconds)" << std::endl;

    if (opts.Verbose)
    {
        std::cout << std::endl;
        std::cout << "Printing matching files: #" << allFiles.size() << std::endl;
        std::cout << "---------------------------------------" << std::endl;
        for (const PathDetails& pd : allFiles)
            std::cout << "Size: " << std::setw(12) << pd.m_size << "  " << pd.m_path << std::endl;
        std::cout << std::endl << std::endl;
    }

    long long timeMilliSec = 0;
    NameBasedGroupVec grouping = filterAndGroupFiles(allFiles, timeMilliSec);
    std::cout << std::endl;
    std::cout << "Found " << grouping.size() << " potential duplicates (" << timeMilliSec << " ms)" << std::endl;

    std::cout << std::endl;

    uint64_t totalRunningSize = 0;
    uint64_t uniqRunningSize = 0;
    for (const NameBasedGroup& ng : grouping)
    {
        std::cout << std::endl;

        const auto& pd = allFiles[ng.m_duplicates.at(0)];

        uniqRunningSize += pd.m_size;

        std::cout << pd.m_path.filename().string() << " " << pd.m_size << " * " << ng.m_duplicates.size() << std::endl;
        std::cout << "---------------------------------------" << std::endl;

        for (int idx = 0; idx < ng.m_duplicates.size(); ++idx)
        {
            const auto& pd2 = allFiles[ng.m_duplicates.at(idx)];

            totalRunningSize += pd2.m_size;
            std::cout << pd2.m_path.string() << std::endl;
        }
    }

    if (totalRunningSize == 0)
    {
        for (const auto& pd : allFiles)
            totalRunningSize += pd.m_size;

        uniqRunningSize = totalRunningSize;
    }

    std::cout << std::endl;

    std::cout << "Size including duplicates: " << totalRunningSize << " (" << toMB(totalRunningSize) << " MB)" << std::endl;
    std::cout << "Size without duplicates:   " << uniqRunningSize  << " (" << toMB(uniqRunningSize)  << " MB)" << std::endl;

    std::cout << std::endl;

    return 0;
}

