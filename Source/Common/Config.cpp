#include "Common/ArgumentLoader.h"
#include "Common/Config.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/Utils/FileLoading.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <FEXHeaderUtils/SymlinkChecks.h>

#include <cstring>
#ifndef _WIN32
#include <linux/limits.h>
#include <pwd.h>
#endif
#include <list>
#include <utility>
#include <json-maker.h>
#include <tiny-json.h>

namespace FEX::Config {
namespace JSON {
  struct JsonAllocator {
    jsonPool_t PoolObject;
    fextl::unique_ptr<fextl::list<json_t>> json_objects;
  };
  static_assert(offsetof(JsonAllocator, PoolObject) == 0, "This needs to be at offset zero");

  json_t* PoolInit(jsonPool_t* Pool) {
    JsonAllocator* alloc = reinterpret_cast<JsonAllocator*>(Pool);
    alloc->json_objects = fextl::make_unique<fextl::list<json_t>>();
    return &*alloc->json_objects->emplace(alloc->json_objects->end());
  }

  json_t* PoolAlloc(jsonPool_t* Pool) {
    JsonAllocator* alloc = reinterpret_cast<JsonAllocator*>(Pool);
    return &*alloc->json_objects->emplace(alloc->json_objects->end());
  }

  static void LoadJSonConfig(const fextl::string &Config, std::function<void(const char *Name, const char *ConfigSring)> Func) {
    fextl::vector<char> Data;
    if (!FEXCore::FileLoading::LoadFile(Data, Config)) {
      return;
    }

    JsonAllocator Pool {
      .PoolObject = {
        .init = PoolInit,
        .alloc = PoolAlloc,
      },
    };

    json_t const *json = json_createWithPool(&Data.at(0), &Pool.PoolObject);
    if (!json) {
      LogMan::Msg::EFmt("Couldn't create json");
      return;
    }

    json_t const* ConfigList = json_getProperty(json, "Config");

    if (!ConfigList) {
      // This is a non-error if the configuration file exists but no Config section
      return;
    }

    for (json_t const* ConfigItem = json_getChild(ConfigList);
      ConfigItem != nullptr;
      ConfigItem = json_getSibling(ConfigItem)) {
      const char* ConfigName = json_getName(ConfigItem);
      const char* ConfigString = json_getValue(ConfigItem);

      if (!ConfigName) {
        LogMan::Msg::EFmt("Couldn't get config name");
        return;
      }

      if (!ConfigString) {
        LogMan::Msg::EFmt("Couldn't get ConfigString for '{}'", ConfigName);
        return;
      }

      Func(ConfigName, ConfigString);
    }
  }
}

  static const fextl::map<FEXCore::Config::ConfigOption, fextl::string> ConfigToNameLookup = {{
#define OPT_BASE(type, group, enum, json, default) {FEXCore::Config::ConfigOption::CONFIG_##enum, #json},
#include <FEXCore/Config/ConfigValues.inl>
  }};

  void SaveLayerToJSON(const fextl::string& Filename, FEXCore::Config::Layer *const Layer) {
    char Buffer[4096];
    char *Dest{};
    Dest = json_objOpen(Buffer, nullptr);
    Dest = json_objOpen(Dest, "Config");
    for (auto &it : Layer->GetOptionMap()) {
      auto &Name = ConfigToNameLookup.find(it.first)->second;
      for (auto &var : it.second) {
        Dest = json_str(Dest, Name.c_str(), var.c_str());
      }
    }
    Dest = json_objClose(Dest);
    Dest = json_objClose(Dest);
    json_end(Dest);

    auto File = FEXCore::File::File(Filename.c_str(),
      FEXCore::File::FileModes::WRITE |
      FEXCore::File::FileModes::CREATE |
      FEXCore::File::FileModes::TRUNCATE);

    if (File.IsValid()) {
      File.Write(Buffer, strlen(Buffer));
    }
  }

  // Application loaders
  class OptionMapper : public FEXCore::Config::Layer {
  public:
    explicit OptionMapper(FEXCore::Config::LayerType Layer);

  protected:
    void MapNameToOption(const char *ConfigName, const char *ConfigString);
  };

  class MainLoader final : public OptionMapper {
  public:
    explicit MainLoader(FEXCore::Config::LayerType Type);
    explicit MainLoader(fextl::string ConfigFile);
    void Load() override;

  private:
    fextl::string Config;
  };

  class AppLoader final : public OptionMapper {
  public:
    explicit AppLoader(const fextl::string& Filename, FEXCore::Config::LayerType Type);
    void Load();

  private:
    fextl::string Config;
  };

  class EnvLoader final : public FEXCore::Config::Layer {
  public:
    explicit EnvLoader(char *const _envp[]);
    void Load() override;

  private:
    char *const *envp;
  };

  static const fextl::map<fextl::string, FEXCore::Config::ConfigOption, std::less<>> ConfigLookup = {{
#define OPT_BASE(type, group, enum, json, default) {#json, FEXCore::Config::ConfigOption::CONFIG_##enum},
#include <FEXCore/Config/ConfigValues.inl>
  }};

  OptionMapper::OptionMapper(FEXCore::Config::LayerType Layer)
    : FEXCore::Config::Layer(Layer) {
  }

  void OptionMapper::MapNameToOption(const char *ConfigName, const char *ConfigString) {
    auto it = ConfigLookup.find(ConfigName);
    if (it != ConfigLookup.end()) {
      Set(it->second, ConfigString);
    }
  }

  static const fextl::vector<std::pair<const char*, FEXCore::Config::ConfigOption>> EnvConfigLookup = {{
#define OPT_BASE(type, group, enum, json, default) {"FEX_" #enum, FEXCore::Config::ConfigOption::CONFIG_##enum},
#include <FEXCore/Config/ConfigValues.inl>
  }};

  MainLoader::MainLoader(FEXCore::Config::LayerType Type)
    : OptionMapper(Type)
    , Config{FEXCore::Config::GetConfigFileLocation(Type == FEXCore::Config::LayerType::LAYER_GLOBAL_MAIN)} {
  }

  MainLoader::MainLoader(fextl::string ConfigFile)
    : OptionMapper(FEXCore::Config::LayerType::LAYER_MAIN)
    , Config{std::move(ConfigFile)} {
  }

  void MainLoader::Load() {
    JSON::LoadJSonConfig(Config, [this](const char *Name, const char *ConfigString) {
      MapNameToOption(Name, ConfigString);
    });
  }

  AppLoader::AppLoader(const fextl::string& Filename, FEXCore::Config::LayerType Type)
    : OptionMapper(Type) {
    const bool Global = Type == FEXCore::Config::LayerType::LAYER_GLOBAL_STEAM_APP ||
                        Type == FEXCore::Config::LayerType::LAYER_GLOBAL_APP;
    Config = FEXCore::Config::GetApplicationConfig(Filename, Global);

    // Immediately load so we can reload the meta layer
    Load();
  }

  void AppLoader::Load() {
    JSON::LoadJSonConfig(Config, [this](const char *Name, const char *ConfigString) {
      MapNameToOption(Name, ConfigString);
    });
  }

  EnvLoader::EnvLoader(char *const _envp[])
    : FEXCore::Config::Layer(FEXCore::Config::LayerType::LAYER_ENVIRONMENT)
    , envp {_envp} {
  }

  void EnvLoader::Load() {
    using EnvMapType = fextl::unordered_map<std::string_view, std::string_view>;
    EnvMapType EnvMap;

    for(const char *const *pvar=envp; pvar && *pvar; pvar++) {
      std::string_view Var(*pvar);
      size_t pos = Var.rfind('=');
      if (fextl::string::npos == pos)
        continue;

      std::string_view Key = Var.substr(0,pos);
      std::string_view Value {Var.substr(pos+1)};

#define ENVLOADER
#include <FEXCore/Config/ConfigOptions.inl>

      EnvMap[Key] = Value;
    }

    auto GetVar = [](EnvMapType &EnvMap, const std::string_view id)  -> std::optional<std::string_view> {
      if (EnvMap.find(id) != EnvMap.end())
        return EnvMap.at(id);

      // If envp[] was empty, search using std::getenv()
      const char* vs = std::getenv(id.data());
      if (vs) {
        return vs;
      }
      else {
        return std::nullopt;
      }
    };

    std::optional<std::string_view> Value;

    for (auto &it : EnvConfigLookup) {
      if ((Value = GetVar(EnvMap, it.first)).has_value()) {
        Set(it.second, fextl::string(*Value));
      }
    }
  }

  fextl::unique_ptr<FEXCore::Config::Layer> CreateGlobalMainLayer() {
    return fextl::make_unique<MainLoader>(FEXCore::Config::LayerType::LAYER_GLOBAL_MAIN);
  }

  fextl::unique_ptr<FEXCore::Config::Layer> CreateMainLayer(fextl::string const *File) {
    if (File) {
      return fextl::make_unique<MainLoader>(*File);
    }
    else {
      return fextl::make_unique<MainLoader>(FEXCore::Config::LayerType::LAYER_MAIN);
    }
  }

  fextl::unique_ptr<FEXCore::Config::Layer> CreateAppLayer(const fextl::string& Filename, FEXCore::Config::LayerType Type) {
    return fextl::make_unique<AppLoader>(Filename, Type);
  }

  fextl::unique_ptr<FEXCore::Config::Layer> CreateEnvironmentLayer(char *const _envp[]) {
    return fextl::make_unique<EnvLoader>(_envp);
  }

  fextl::string RecoverGuestProgramFilename(fextl::string Program, bool ExecFDInterp, const std::string_view ProgramFDFromEnv) {
    // If executed with a FEX FD then the Program argument might be empty.
    // In this case we need to scan the FD node to recover the application binary that exists on disk.
    // Only do this if the Program argument is empty, since we would prefer the application's expectation
    // of application name.
    if (!ProgramFDFromEnv.empty() && Program.empty()) {
      // Get the `dev` node of the execveat fd string.
      Program = "/dev/fd/";
      Program += ProgramFDFromEnv;
    }

    // If we were provided a relative path then we need to canonicalize it to become absolute.
    // If the program name isn't resolved to an absolute path then glibc breaks inside it's `_dl_get_origin` function.
    // This is because we rewrite `/proc/self/exe` to the absolute program path calculated in here.
    if (!Program.starts_with('/')) {
      char ExistsTempPath[PATH_MAX];
      char *RealPath = FHU::Filesystem::Absolute(Program.c_str(), ExistsTempPath);
      if (RealPath) {
        Program = RealPath;
      }
    }

    // If FEX was invoked through an FD path (either binfmt_misc or execveat) then we need to check the
    // Program to see if it is a symlink to find the real path.
    //
    // binfmt_misc: Arg[0] is actually the execve `pathname` argument or `/dev/fd/<FD>` path
    //   - `pathname` with execve (See Side Note)
    //   - FD path with execveat and FD doesn't have an existing file on the disk
    //
    // ProgramFDFromEnv: Arg[0] is Application provided data or `/dev/fd/<FD>` from above fix-up.
    //   - execveat was either passed no arguments (argv=NULL) or the first argument is an empty string (argv[0]="").
    //   - FD path with execveat and FD doesn't have an existing file on the disk
    //
    // Side Note:
    //  The `execve` syscall doesn't take an FD but binfmt_misc will give FEX an FD to execute still.
    //  Arg[0] will always contain the `pathname` argument provided to execve.
    //  It does not resolve symlinks, and it does not convert the path to absolute.
    //
    // Examples:
    //  - Regular execve. Application must exist on disk.
    //    execve binfmt_misc args layout:   `FEXInterpreter <Path provided to execve pathname> <user provided argv[0]> <user provided argv[n]>...`
    //  - Regular execveat with FD. FD is backed by application on disk.
    //    execveat binfmt_misc args layout: `FEXInterpreter <Path provided to execve pathname> <user provided argv[0]> <user provided argv[n]>...`
    //  - Regular execveat with FD. FD points to file on disk that has been deleted.
    //    execveat binfmt_misc args layout: `FEXInterpreter /dev/fd/<FD> <user provided argv[0]> <user provided argv[n]>...`
#ifndef _WIN32
    if (ExecFDInterp || !ProgramFDFromEnv.empty()) {
      // Only in the case that FEX is executing an FD will the program argument potentially be a symlink.
      // This symlink will be in the style of `/dev/fd/<FD>`.
      //
      // If the argument /is/ a symlink then resolve its path to get the original application name.
      if (FHU::Symlinks::IsSymlink(Program)) {
        char Filename[PATH_MAX];
        auto SymlinkPath = FHU::Symlinks::ResolveSymlink(Program, Filename);
        if (SymlinkPath.starts_with('/')) {
          // This file was executed through an FD.
          // Remove the ` (deleted)` text if the file was deleted after the fact.
          // Otherwise just get the symlink without the deleted text.
          return fextl::string{SymlinkPath.substr(0, SymlinkPath.rfind(" (deleted)"))};
        }
      }
    }
#endif

    return Program;
  }

  ApplicationNames LoadConfig(
    bool NoFEXArguments,
    bool LoadProgramConfig,
    int argc,
    char **argv,
    char **const envp,
    bool ExecFDInterp,
    const std::string_view ProgramFDFromEnv) {
    FEX::Config::InitializeConfigs();
    FEXCore::Config::Initialize();
    FEXCore::Config::AddLayer(CreateGlobalMainLayer());
    FEXCore::Config::AddLayer(CreateMainLayer());

    if (NoFEXArguments) {
      FEX::ArgLoader::LoadWithoutArguments(argc, argv);
    }
    else {
      FEXCore::Config::AddLayer(fextl::make_unique<FEX::ArgLoader::ArgLoader>(argc, argv));
    }

    FEXCore::Config::AddLayer(CreateEnvironmentLayer(envp));
    FEXCore::Config::Load();

    auto Args = FEX::ArgLoader::Get();

    if (LoadProgramConfig) {
      if (Args.empty()) {
        // Early exit if we weren't passed an argument
        return {};
      }

      Args[0] = RecoverGuestProgramFilename(std::move(Args[0]), ExecFDInterp, ProgramFDFromEnv);
      fextl::string& Program = Args[0];

      bool Wine = false;
      fextl::string ProgramName;
      for (size_t CurrentProgramNameIndex = 0; CurrentProgramNameIndex < Args.size(); ++CurrentProgramNameIndex) {
        auto CurrentProgramName = FHU::Filesystem::GetFilename(Args[CurrentProgramNameIndex]);

        if (CurrentProgramName == "wine-preloader" ||
            CurrentProgramName == "wine64-preloader") {
          // Wine preloader is required to be in the format of `wine-preloader <wine executable>`
          // The preloader doesn't execve the executable, instead maps it directly itself
          // Skip the next argument since we know it is wine (potentially with custom wine executable name)
          ++CurrentProgramNameIndex;
          Wine = true;
        }
        else if(CurrentProgramName == "wine" ||
                CurrentProgramName == "wine64") {
          // Next argument, this isn't the program we want
          //
          // If we are running wine or wine64 then we should check the next argument for the application name instead.
          // wine will change the active program name with `setprogname` or `prctl(PR_SET_NAME`.
          // Since FEX needs this data far earlier than libraries we need a different check.
          Wine = true;
        }
        else {
          if (Wine == true) {
            // If this was path separated with '\' then we need to check that.
            auto WinSeparator = CurrentProgramName.find_last_of('\\');
            if (WinSeparator != CurrentProgramName.npos) {
              // Used windows separators
              CurrentProgramName = CurrentProgramName.substr(WinSeparator + 1);
            }
          }

          ProgramName = CurrentProgramName;

          // Past any wine program names
          break;
        }
      }

      FEXCore::Config::AddLayer(CreateAppLayer(ProgramName, FEXCore::Config::LayerType::LAYER_GLOBAL_APP));
      FEXCore::Config::AddLayer(CreateAppLayer(ProgramName, FEXCore::Config::LayerType::LAYER_LOCAL_APP));

      auto SteamID = getenv("SteamAppId");
      if (SteamID) {
        // If a SteamID exists then let's search for Steam application configs as well.
        // We want to key off both the SteamAppId number /and/ the executable since we may not want to thunk all binaries.
        fextl::string SteamAppName = fextl::fmt::format("Steam_{}_{}", SteamID, ProgramName);
        FEXCore::Config::AddLayer(CreateAppLayer(SteamAppName, FEXCore::Config::LayerType::LAYER_GLOBAL_STEAM_APP));
        FEXCore::Config::AddLayer(CreateAppLayer(SteamAppName, FEXCore::Config::LayerType::LAYER_LOCAL_STEAM_APP));
      }

      return ApplicationNames{std::move(Program), std::move(ProgramName)};
    }
    return {};
  }

#ifndef _WIN32
  char const* FindUserHomeThroughUID() {
    auto passwd = getpwuid(geteuid());
    if (passwd) {
      return passwd->pw_dir;
    }
    return nullptr;
  }

  const char *GetHomeDirectory() {
    char const *HomeDir = getenv("HOME");

    // Try to get home directory from uid
    if (!HomeDir) {
      HomeDir = FindUserHomeThroughUID();
    }

    // try the PWD
    if (!HomeDir) {
      HomeDir = getenv("PWD");
    }

    // Still doesn't exit? You get local
    if (!HomeDir) {
      HomeDir = ".";
    }

    return HomeDir;
  }

  fextl::string GetDataDirectory() {
    fextl::string DataDir{};

    char const *HomeDir = GetHomeDirectory();
    char const *DataXDG = getenv("XDG_DATA_HOME");
    char const *DataOverride = getenv("FEX_APP_DATA_LOCATION");
    if (DataOverride) {
      // Data override will override the complete directory
      DataDir = DataOverride;
    }
    else {
      DataDir = DataXDG ?: HomeDir;
      DataDir += "/.fex-emu/";
    }
    return DataDir;
  }

  fextl::string GetConfigDirectory(bool Global) {
    fextl::string ConfigDir;
    if (Global) {
      ConfigDir = GLOBAL_DATA_DIRECTORY;
    }
    else {
      char const *HomeDir = GetHomeDirectory();
      char const *ConfigXDG = getenv("XDG_CONFIG_HOME");
      char const *ConfigOverride = getenv("FEX_APP_CONFIG_LOCATION");
      if (ConfigOverride) {
        // Config override completely overrides the config directory
        ConfigDir = ConfigOverride;
      }
      else {
        ConfigDir = ConfigXDG ? ConfigXDG : HomeDir;
        ConfigDir += "/.fex-emu/";
      }

      // Ensure the folder structure is created for our configuration
      if (!FHU::Filesystem::Exists(ConfigDir) &&
          !FHU::Filesystem::CreateDirectories(ConfigDir)) {
        // Let's go local in this case
        return "./";
      }
    }

    return ConfigDir;
  }

  fextl::string GetConfigFileLocation(bool Global) {
    fextl::string ConfigFile{};
    if (Global) {
      ConfigFile = GetConfigDirectory(true) + "Config.json";
    }
    else {
      const char *AppConfig = getenv("FEX_APP_CONFIG");
      if (AppConfig) {
        // App config environment variable overwrites only the config file
        ConfigFile = AppConfig;
      }
      else {
        ConfigFile = GetConfigDirectory(false) + "Config.json";
      }
    }
    return ConfigFile;
  }

  void InitializeConfigs() {
    FEXCore::Config::SetDataDirectory(GetDataDirectory());
    FEXCore::Config::SetConfigDirectory(GetConfigDirectory(false), false);
    FEXCore::Config::SetConfigDirectory(GetConfigDirectory(true), true);
    FEXCore::Config::SetConfigFileLocation(GetConfigFileLocation(false), false);
    FEXCore::Config::SetConfigFileLocation(GetConfigFileLocation(true), true);
  }
#else
  void InitializeConfigs() {
    // TODO: Find out how to set this up on WIN32.
    LogMan::Msg::EFmt("{} Unsupported on WIN32!", __func__);
  }
#endif
}
