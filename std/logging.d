// Written in the D programming language.
// XXX inspect all the try statements
// XXX fix the API so that user doesn't need to init 
// XXX inspect all the formattedWrite and see what could be optimized
// XXX remove the use of text!
// XXX Allow the configuration of the log file name
// XXX Allow the configuration of the log line

/++
Implements application level _logging mechanism.

This module defines a set of functions useful for many common _logging tasks.  The module must be initialized (ideally in single threaded mode) by calling $(D initializeLogging). Messages of different severity level are logged by calling the template function $(D log). Verbose messages can be logged by calling the template function $(D vlog).

Examples:
---
import std.logging;

int main(string[] args)
{
   initLogging(SharedLogger.getCreator(args[0]));

   info.format("You passed %s argument(s)", args.length - 1);
   info.when(args.length > 1)("Arguments: ", args[1 .. $]);

   info("This is an info message.");
   warning("This is a warning message.");
   error("This is an error message!");
   dfatal("This is a debug fatal message");

   vlog(0)("Verbosity 0 message");
   vlog(1)("Verbosity 1 message");
   vlog(2)("Verbosity 2 message");

   foreach (i; 0 .. 10)
   {
      info.when(every(9))("Every nine");
 
      auto logger = info;
      if(logger.willLog)
      {
         auto message = "Cool message";
         // perform some complex operation
         // ...
         logger(message);
      }

      vlog(2).when(first)("Verbose message only on the first iterations");
   }

   fatal("This is a fatal message!!!");
}
---

Note:
Compile time disabling of severity levels can be done by defining the LOGGING_FATAL_DISABLED, LOGGING_ERROR_DISABLED, LOGGING_WARNING_DISABLED or LOGGING_INFO_DISABLED version. Disabiliting a higher severity level will disable all the lower severity level. E.g. LOGGING_WARNING_DISABLED will disable warning and info serverity levels at compile time and enable the fatal and error serverity level.

Verbose messages are logged at the info severity level so using LOGGING_INFO_DISABLED will also disable versbose messages.

Macros:
D = $(B$(U $0))
+/
module std.logging;

import core.atomic : cas;
import core.thread : Thread;
import core.sync.mutex : Mutex;
import std.stdio : File, stderr, writefln;
import std.string : newline;
import std.conv : text, to;
import std.datetime: Clock, DateTime;
import std.exception : enforce;
import std.getopt : getopt;
import std.process : getenv;
import std.array : Appender, appender, array;
import std.format : formattedWrite;
import std.path : fnmatch, join;
import std.algorithm : endsWith, startsWith, splitter, swap;

version(unittest)
{
   import std.array : replicate;
   import std.file : remove;
   import core.exception : AssertError;
}

/++
Defines the severity levels supported by the logging library.

Logging messages of severity level fatal will also cause the program to halt. The dfatal severity will log at a fatal severity in debug mode and at a error severity in release mode.
+/
enum Severity
{
   fatal = 0,
   error,
   warning,
   info
}

immutable string[] severityNames = [ "FATAL", "ERROR", "WARNING", "INFO" ];

version(strip_log_fatal) NoopLogger fatal;
else DefaultLogger fatal;

version(strip_log_error) NoopLogger error;
else typeof(fatal) error;

version(strip_log_warning) NoopLogger warning;
else typeof(error) warning;

version(strip_log_info) NoopLogger info;
else typeof(warning) info;

debug alias fatal dfatal;
else alias error dfatal;

/++
Initializes the logging infrastructure.

This function must be called once before calling any of the logging functions.

Params:
   logCreator = Delegate which creates the Logger used by the module.
   filterConfig = Module configuration object. 

See_Also:
   FilterConfig
+/
void initLogging(ref string[] commandLine)
{
   auto filterConfig = FilterConfig.create(commandLine);
   auto loggerConfig = LoggerConfig.create(commandLine);

   initializeLogging!SharedLogger(loggerConfig, filterConfig);
}

void initializeLogging(T : Logger, BC)
                      (BC loggerConfig,
                       FilterConfig filterConfig = FilterConfig())
{
   auto logger = new T(loggerConfig);
   _moduleConfig.init(logger, filterConfig);
}

/++
Logs a message.

Returns a structure for logging messages at the specified severity.
Example:
---
   log!error.write("Log an ", severityNames[error], " message!");
   log!error.format("Also logs an %s message!", severityNames[error]);
---

You can also performed conditional logging.
Example:


---
   void coolFunction(Object object)
   {
      log!fatal(object is null).write("I don't like null objects!");
      // ...
   }

   foreach(i; 0 .. 10)
   {
      log!info(first).write("Only log this the first time in the loop");
   }
---

The returned object can be reused.
Example:
---
   auto logger = log!warning;
   with(logger)
   {
      if(willLog)
      {
         auto message = "A complex message...";
         // Continue constructing 'message'...

         write(message);
      }
   }
---

+/

/++
Logs a verbose message.

Returns a structure for logging messages at the specified verbose level.
Example:
---
   vlog(0).write("Log a verbose ", 0, " message!");
   vlog(2).format("Also logs a verbose %s message!", 0);
---

You can also performed conditional verbose logging.
Example:
---
   foreach(i; 0 .. 10)
   {
      vlog(3, first).write("Only log this the first time in the loop");
   }
---

The returned object can be reused.
Example:
---
   auto logger = vlog(1);
   with(logger)
   {
      if(willLog)
      {
         auto message = "A complex message...";
         // Continue constructing 'message'...

         write(message);
      }
   }
---
+/

static if(is(typeof(info) == NoopLogger))
{
   ref NoopLogger vlog(short level,
                       string file = __FILE__)
   {
      return info;
   }
}
else
{
   VerboseLogger vlog(short level,
                      string file = __FILE__)
   {
      return VerboseLogger.create(level, _moduleConfig, &info, file);
   }
}

struct NoopLogger
{
   @property bool willLog() const { return false; }

   ref NoopLogger when(lazy bool now) { return this; }
   void opCall(T...)(lazy T args) {}
   alias opCall write;
   void format(T...)(lazy string fmt, lazy T args) {}
}

unittest
{
   // assert default values
   FilterConfig filterConfig;
   assert(filterConfig._maxSeverity == Severity.error);
   assert(filterConfig._maxVerboseLevel == short.min);
   assert(filterConfig._vModuleConfigs == null);

   auto name = "program_name";
   auto args = [name,
                "--" ~ FilterConfig.maxSeverityFlag, "info",
                "--" ~ FilterConfig.verboseModuleFlag, "*logging=2,module=0",
                "--" ~ FilterConfig.maxVerboseLevelFlag, "2",
                "--ignoredOption"];
               
   filterConfig = FilterConfig.create(args);

   // assert that all expected options where removed
   assert(args.length == 2);
   assert(args[0] == name);

   assert(filterConfig._maxSeverity == Severity.info);
   assert(filterConfig._maxVerboseLevel == 2);

   // assert VModuleConfig entries
   assert(filterConfig._vModuleConfigs.length == 2);

   assert(filterConfig._vModuleConfigs[0].match("std/logging.d", 2));
   assert(filterConfig._vModuleConfigs[1].match("module.d", 0));

   // this(this)
   auto tempFilter = filterConfig;
   assert(tempFilter._vModuleConfigs == filterConfig._vModuleConfigs);
   assert(tempFilter._vModuleConfigs !is filterConfig._vModuleConfigs);

   // opAssign
   tempFilter = filterConfig;
   assert(tempFilter._vModuleConfigs == filterConfig._vModuleConfigs);
   assert(tempFilter._vModuleConfigs !is filterConfig._vModuleConfigs);
}

/++
Configuration struct for the module.

This object must be used to configure the logging module at initialization.  All the properties are optional and can be use to configure the framework's behavior.
+/
struct FilterConfig
{
   static string maxSeverityFlag = "maxloglevel";
   static string verboseModuleFlag = "vmodule";
   static string maxVerboseLevelFlag = "v";

   static FilterConfig create(ref string[] commandLine)
   {
      FilterConfig filterConfig;

      void handleModuleConfig(string option, string value)
      {
         assert(option == verboseModuleFlag);
         filterConfig.vModuleConfigs = VModuleConfig.create(value);
      }

      getopt(commandLine,
             std.getopt.config.passThrough,
             maxSeverityFlag, &filterConfig._maxSeverity,
             verboseModuleFlag, &handleModuleConfig,
             maxVerboseLevelFlag, &filterConfig._maxVerboseLevel);

      return filterConfig;
   }

   this(this) { _vModuleConfigs = _vModuleConfigs.dup; }

   ref FilterConfig opAssign(FilterConfig filterConfig)
   {
      swap(this, filterConfig);
      return this;
   }

/++
Severity to use for _logging.

The logging framework will only log messages with a severity greater than or equal to the value of this property.
+/
   @property void maxSeverity(Severity severity)
   {
      _maxSeverity = severity;
   }

/++
+/
   @property void maxVerboseLevel(short maxVerboseLevel)
   {
      _maxVerboseLevel = maxVerboseLevel;
   }
/++
   XXX talk about how this override maxVerboseLevel
Verbose logging configuration.

Messages logged by using the template function $(D vlog) or $(D vlogf) will be filtered by comparing against each VModuleConfig until a match is found. If no match is found the verbose message will not get logged.

See_Also:
   VModuleConfig
+/
   @property void vModuleConfigs(VModuleConfig[] vModuleConfigs)
   {
      _vModuleConfigs = vModuleConfigs;
   }

/++
Function pointer for handling log message with a severity of fatal.

This function will be called by the thread trying to log a fatal message by using $(D log) or $(D logf). The function $(I fatalHandler) should not return; otherwise the framework will assert(false).
+/
   @property void fatalHandler(void function() fatalHandler)
   {
      _fatalHandler = fatalHandler;
   }

   private Severity _maxSeverity = Severity.error;
   private short _maxVerboseLevel = short.min;
   private VModuleConfig[] _vModuleConfigs;
   private void function() _fatalHandler;
}

version(unittest)
{
   // Test severity filtering
   class SeverityFilter : Logger
   {
      shared void log(const ref LogMessage msg)
      {
         called = true;
         severity = msg.severity;
         message = cast(shared)msg.message;
      }

      shared void flush()
      {
         flushCalled = true;
      }

      shared void clear()
      {
         message = string.init;
         called = false;
         flushCalled = false;
      }

      const(char)[] message;
      Severity severity;
      bool called;
      bool flushCalled;
   }
}

unittest
{
   DefaultLogger logInfo;
   DefaultLogger logWarning;
   DefaultLogger logError;
   DefaultLogger logFatal;

   ModuleConfig testConfig;

   // logger shouldn't log if not init
   assert(!logInfo.willLog);

   // logger should throw if init but module config is not init
   logInfo.init(Severity.info, &testConfig);
   try { logInfo.willLog; assert(false); } catch(Exception e) {}

   FilterConfig filterConfig;
   filterConfig.maxSeverity = Severity.warning;

   auto logger = cast(shared) new SeverityFilter();

   testConfig.init(logger, filterConfig);

   logWarning.init(Severity.warning, &testConfig);
   logError.init(Severity.error, &testConfig);
   logFatal.init(Severity.fatal, &testConfig);

   auto loggedMessage = "logged message";

   // Test willLog
   assert(!logInfo.willLog);
   assert(logWarning.willLog);
   assert(logError.willLog);
   assert(logFatal.willLog);

   // Test logging and severity filtering
   logInfo(loggedMessage);
   assert(!logger.called);

   logger.clear();
   logWarning(loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   logger.clear();
   logError(loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.error &&
          logger.message == loggedMessage);

   logger.clear();
   logError.format("%s", loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.error &&
          logger.message == loggedMessage);

   logger.clear();
   try { logFatal(loggedMessage); assert(false); } catch (AssertError e) {}
   assert(logger.called);
   assert(logger.severity == Severity.fatal &&
          logger.message == loggedMessage);
   assert(logger.flushCalled);

   logger.clear();
   logWarning.format("%s", loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   // logInfo didn't log so when(true) shouldn't log either
   assert(!logInfo.when(true).willLog);

   // LogWarning would log so when(true) should log also
   assert(logWarning.when(true).willLog);

   // when(false) shouldn't log
   assert(!logError.when(false).willLog);
}

struct DefaultLogger
{
   private void init(Severity severity, shared(ModuleConfig)* config)
   {
      _config = config;

      _message.severity = severity;
      _message.threadId = Thread.getThis.threadId;
   }

/++
Returns true when write and format will lead to a message being logged.
+/
   @property bool willLog() const
   {
      enforce(_config is null || (cast(shared)_config).isInitialized);
      return _config !is null && _message.severity <= (cast(shared)_config).severity;
   }

/++
+/
   DefaultLogger when(lazy bool now)
   {
      if(willLog && now) return this;

      return _noopLogger;
   }
   
/++
Records each argument in one log line or record.

Example:
---
   auto pi = 3.14159265;

   auto logger = log!info;
   logger.write("The value of pi is ", pi);

   // The same as above...
   log!info.write("The value of pi is ", pi);
---
+/
   void opCall(string file = __FILE__, int line = __LINE__, T...)(lazy T args)
   {
      // XXX change this to use formattedWrite's new format string
      if(willLog)
      {
         /// XXX move this to format when I start using the new formattedWrite
         _message.file = file;
         _message.line = line;
         log(_message, args);
      }
   }
   alias opCall write; /// ditto

/++
Records formatted message in one log line or record.

Example:
---
   auto goldenRatio = 1.61803399;

   auto logger = log!info;
   logger.format("The number %s is the golden ratio", goldenRatio);

   // The same as above...
   log!info.format("The number %s is the golden ratio", goldenRatio);
---
+/
   void format(string file = __FILE__, int line = __LINE__, T...)
              (lazy string fmt, lazy T args)
   {
      if(willLog)
      {
         _message.file = file;
         _message.line = line;
         logf(_message, fmt, args);
      }
   }

   private void log(T...)(ref Logger.LogMessage message, T args)
   {
      assert(willLog);

      // record message
      _writer.clear(); // XXX make sure clear doesn't deallocate mem
      foreach(T, arg; args) _writer.put(to!(char[])(arg));
      message.message = _writer.data;

      // record the time stamp
      message.time = Clock.currTime.stdTime;

      scope(exit)
      {
         if(message.severity == Severity.fatal)
         {
            /+
             + The other of the scope(exit) is important. We want
             + _fatalHandler to run before the assert.
             +/
            scope(exit) assert(false);
            scope(exit) _config.fatalHandler(); 
            _config.logger.flush();
         }
      }

      _config.logger.log(message);
   }

   private void logf(T...)(ref Logger.LogMessage message, string fmt, T args)
   {
      assert(willLog);

      // record message
      _writer.clear(); // XXX make sure clear doesn't deallocate mem
      _writer.reserve(fmt.length);
      formattedWrite(_writer, fmt, args);
      message.message = _writer.data;

      // record the time stamp
      message.time = Clock.currTime.stdTime;

      scope(exit)
      {
         if(message.severity == Severity.fatal)
         {
            /+
             + The other of the scope(exit) is important. We want
             + _fatalHandler to run before the assert.
             +/
            scope(exit) assert(false);
            scope(exit) _config.fatalHandler(); 
            _config.logger.flush();
         }
      }

      _config.logger.log(message);
   }

   private @property Severity severity()
   {
      assert(_config); // assert that it was initialized
      return _message.severity;
   }

   private Logger.LogMessage _message;
   private Appender!(char[]) _writer;

   private shared ModuleConfig* _config;

   private static __gshared DefaultLogger _noopLogger;
}

unittest
{
   auto loggedMessage = "Verbose log message";

   DefaultLogger logInfo;
   DefaultLogger logWarning;
   VerboseLogger verboseLog;
   ModuleConfig testConfig;

   logInfo.init(Severity.info, &testConfig);
   logWarning.init(Severity.warning, &testConfig);

   // verbose logging shouldn't throw if module not init
   try { verboseLog = VerboseLogger.create(0, testConfig, &logWarning);
         assert(false); } catch(Exception e) {}

   FilterConfig filterConfig;
   filterConfig.maxSeverity = Severity.warning;
   filterConfig.maxVerboseLevel = 3;
   filterConfig.vModuleConfigs = VModuleConfig.create("*logging.d=2");

   auto logger = cast(shared) new SeverityFilter();

   testConfig.init(logger, filterConfig);

   // Test vlogging and module filtering
   logger.clear();
   verboseLog = VerboseLogger.create(2, testConfig, &logWarning);
   assert(verboseLog.willLog);
   verboseLog(loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   // test format
   logger.clear();
   verboseLog.format("%s", loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   // test large verbose level
   logger.clear();
   verboseLog = VerboseLogger.create(3, testConfig, &logWarning);
   verboseLog(loggedMessage);
   assert(!logger.called);

   // test wrong module
   logger.clear();
   verboseLog = VerboseLogger.create(4, testConfig, &logWarning, "not_this");
   verboseLog.format("%s", loggedMessage);
   assert(!logger.called); 

   // test verbose level
   logger.clear();
   verboseLog = VerboseLogger.create(3, testConfig, &logWarning, "not_this");
   verboseLog.format("%s", loggedMessage);
   assert(logger.called); 
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   // test severity config too high
   logger.clear();
   verboseLog = VerboseLogger.create(2, testConfig, &logInfo);
   assert(!verboseLog.willLog);
   verboseLog.format("%s", loggedMessage);
   assert(!logger.called); 
}

struct VerboseLogger
{
   private static VerboseLogger create(short level,
                                       ref shared(ModuleConfig) config,
                                       DefaultLogger* logger,
                                       string file = __FILE__)
   {
      enforce(config.isInitialized);

      if(logger.willLog &&
         logMatches(file, level, config.verboseLevel, config.vModuleConfigs))
      {
         VerboseLogger vlogger;
         vlogger._message.severity = logger.severity;
         vlogger._message.threadId = Thread.getThis.threadId;
         vlogger._message.isVerbose = true;
         vlogger._message.verbose = level;

         vlogger._logger = logger;

         return vlogger;
      }

      return VerboseLogger._verboseNoop;
   }

   @property bool willLog() const
   {
      return _logger !is null && _message.isVerbose && _logger.willLog;
   }

   ref VerboseLogger when(lazy bool now)
   {
      if(willLog && now)
      {
         return this;
      }

      return _verboseNoop;
   }

   void opCall(string file = __FILE__, int line = __LINE__, T...)
              (lazy T args)
   {
      if(willLog)
      {
         /// XXX move this to format
         _message.file = file;
         _message.line = line;
         _logger.log(_message, args);
      }
   }
   alias opCall write;

   void format(string file = __FILE__, int line = __LINE__, T...)
              (lazy string fmt, lazy T args)
   {
      if(willLog)
      {
         _message.file = file;
         _message.line = line;
         _logger.logf(_message, fmt, args);
      }
   }

   private Logger.LogMessage _message;
   private DefaultLogger* _logger;

   private static __gshared VerboseLogger _verboseNoop;
}

unittest
{
}

private shared struct ModuleConfig
{
   void init(shared(Logger) logger,
             FilterConfig filterConfig)
   {
      enforce(logger);
      enforce(cas(&_initializing, false, true));
      scope(success) _initialized = true;

      _vModuleConfigs = filterConfig._vModuleConfigs.idup;

      _logger = logger;

      _severity = filterConfig._maxSeverity;

      _fatalHandler =  filterConfig._fatalHandler ?
                       filterConfig._fatalHandler :
                       function {};

      _verboseLevel = filterConfig._maxVerboseLevel;
   }

   bool isInitialized()
   {
      return _initialized;
   }

   @property shared(Logger) logger()
   {
      assert(_initialized);
      return _logger;
   }

   @property Severity severity()
   {
      assert(_initialized);
      return _severity;
   }

   @property short verboseLevel()
   {
      assert(_initialized);
      return _verboseLevel;
   }

   @property immutable(VModuleConfig)[] vModuleConfigs()
   {
      assert(_initialized);
      return _vModuleConfigs;
   }

   @property void function() fatalHandler()
   {
      assert(_initialized);
      return _fatalHandler;
   }

   private bool _initializing;
   private bool _initialized;

   private Logger _logger;
   private Severity _severity;
   private short _verboseLevel;
   private immutable(VModuleConfig)[] _vModuleConfigs;
   private __gshared void function() _fatalHandler;
}

unittest
{
   // Test equals
   VModuleConfig[] configs = [ VModuleConfig("package/module", 1) ];
   assert(logMatches("package/module", 1, -1, configs));
   assert(logMatches("package/module.d", 1, -1, configs));
   assert(logMatches("package/module", 0, -1, configs));

   assert(!logMatches("module", 1, -1, configs));
   assert(!logMatches("package/module", 2, 3, configs));

   // Test starts with
   configs[0] = VModuleConfig("package*", 1);
   assert(logMatches("package/module", 1, -1, configs));
   assert(logMatches("package/module.d", 1, -1, configs));
   assert(logMatches("package/module", 0, -1, configs));
   assert(logMatches("package/another.d", 1, -1, configs));

   assert(!logMatches("module", 1, -1, configs));
   assert(!logMatches("another/package/module", 1, -1, configs));
   assert(!logMatches("package/module.d", 2, 3, configs));

   // Test ends with
   configs[0] = VModuleConfig("*module", 1);
   assert(logMatches("package/module", 1, -1, configs));
   assert(logMatches("package/module.d", 1, -1, configs));
   assert(logMatches("package/module", 0, -1, configs));
   assert(logMatches("module", 1, -1, configs));

   assert(!logMatches("another", 1, -1, configs));
   assert(!logMatches("package/module", 2, 3, configs));

   // Test global max verbose level
   assert(logMatches("package", 2, 2, configs));
}

/+
 + Returns true when it matched an entry in configs, or when the file doesn't
 + match an entry in configs and level is less <= maxLevel.
 +/
private bool logMatches(string file,
                        short level,
                        short maxLevel,
                        const VModuleConfig[] configs)
{
   bool matchedAFile;
   foreach(config; configs)
   {
      auto result = config.match(file, level);
      if (result == VModuleConfig.Match.yes) return true;
      
      matchedAFile = matchedAFile || (result == VModuleConfig.Match.file);
   }

   return !matchedAFile && level <= maxLevel;
} 

unittest
{
   auto vmodule = "module=1,*another=3,even*=2,module?=0,*module?=1";
   auto result = VModuleConfig.create(vmodule);
   assert(result.length == 5);

   assert(result[0].match("module", 1));
   assert(result[0].match("module.d", 1));
   assert(!result[0].match("amodule", 1));
        
   // Test *
   assert(result[1].match("package/another", 3));
   assert(result[1].match("package/another.d", 3));
   assert(!result[1].match("package/module", 3));

   assert(result[2].match("evenmore", 2));
   assert(result[2].match("evenmore.d", 2));
   assert(!result[2].match("package/evenmore.d", 2));

   // Test ?
   assert(result[3].match("modules.d", 0));
   assert(!result[3].match("module", 0));

   // Test * and ?
   assert(result[4].match("package/modules.d", 1));
   assert(!result[4].match("package/moduleis.d", 1));
   assert(!result[4].match("package/module", 1));

   // Test invalid strings
   try
   {
      VModuleConfig.create("module=2,");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VModuleConfig.create("module=a");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VModuleConfig.create("module=2,another=");
      assert(false);
   }
   catch (Exception e) {}
}

/++
Structure for configuring verbose logging.

This structure is used to control verbose logging on a per module basis. A verbose message with level $(I x) will get logged at severity level info if there is a VModuleConfig entry that matches to the source file and the verbose level of that entry is greater than or equal to $(I x).
+/
struct VModuleConfig
{
/++
Creates an array of $(D VModuleConfig) based on a configuration string.

The format of the configuration string is as follow "$(B [pattern])=$(B [level]),...", where $(B [pattern]) may contain any character allowed in a file name and $(B [level]) must be convertible to an positive integer (greater than or equal to zero). If $(B [pattern]) contains a '*' then it must be at the start or the end. If $(B [pattern]) ends with a '*' then it will match any source file name that starts with the rest of $(B [pattern]). If $(B [pattern]) starts with a '*' then it will match any source file name that ends with a the rest of $(B [pattern]).

For every $(B [pattern])=$(B [level]) in the configuration string a $(D VModuleConfig) will be created and included in the returned array.

Example:
---
auto configs = VModuleConfig.create("special/module=2,great/*=3,*/test=1");
---

The code above will return a verbose logging configuration that will:
$(DL
$(DD 1. Log verbose 2 and lower messages from special/module{,.d})
$(DD 2. Log verbose 3 and lower messages from package great)
$(DD 3. Log verbose 1 and lower messages from any file that ends with test{,.d})
)
+/
   static VModuleConfig[] create(string config)
   {
      VModuleConfig[] result;
      foreach(entry; splitter(config, ","))
      {
         enforce(entry != "");

         auto entryParts = array(splitter(entry, "="));
         enforce(entryParts.length == 2);
         enforce(entryParts[0] != "");

         result ~= VModuleConfig(entryParts[0], to!short(entryParts[1]));
      }

      return result;
   }

   private enum Match { no, yes, file }

   private Match match(string file, short level) const
   { 
      foreach(pattern; _patterns)
      {
         if(fnmatch(file, pattern))
         {
            if(level <= _level) return Match.yes;

            return Match.file;
         }
      }

      return Match.no;
   }

   private this(string pattern, short level)
   {
      _patterns[0] = pattern;
      if(!endsWith(pattern, ".d")) _patterns[1] = pattern ~ ".d";

      _level = level;
   }

   private string[2] _patterns;
   private short _level;
}

/++
Extension point for the module.
+/
interface Logger
{
   public static struct LogMessage
   {
      string file;
      int line;
      Severity severity;
      int threadId;
      char[] message;
      long time;

      bool isVerbose;
      short verbose;

      string logLine() const
      {
         auto writer = appender!string();

         if(isVerbose) formattedWrite(writer,
                                      verboseFormat,
                                      file,
                                      line,
                                      verbose,
                                      threadId,
                                      time,
                                      message,
                                      newline);
         else formattedWrite(writer,
                             severityFormat,
                             file,
                             line,
                             severityNames[severity],
                             threadId,
                             time,
                             message,
                             newline);


         return writer.data;
      }

      static string severityFormat = "%s:%s:%s:%x:%x %s%s";
      static string verboseFormat = "%s:%s:VLOG(%s):%x:%x %s%s";

   }

/++
Logs a message.

The method is called by the logging module whenever it decides that a message should be logged. It is recommend that the implementation of this method doesn't perform any filtering based on severity since at this point all configured filters were applied.

The method is allow to return immediately without persisting the message.
+/
   shared void log(const ref LogMessage message);

/++
Flushes pending log operations.

The method is called by the logging framework whenever it requires that the persistence of all previous log messages. For example the method is called when the client logs a fatal message.

The method must not return until all pending log operations complete.
+/
   shared void flush();
}

unittest
{
   auto name = "program_name";
   // assert default values
   auto loggerConfig = LoggerConfig(name);
   assert(loggerConfig.loggerName == name);
   assert(loggerConfig.logToStderr == false);
   assert(loggerConfig.stderrThreshold == Severity.error);
   // can't test logDirectory as it is env dependent

   auto args = [name,
                "--" ~ LoggerConfig.logToStderrFlag,
                "--" ~ LoggerConfig.stderrThresholdFlag, "fatal",
                "--" ~ LoggerConfig.logDirectoryFlag, "/tmp",
                "--ignoredOption"];

   loggerConfig = LoggerConfig.create(args);
   assert(args.length == 2);
   assert(args[0] == name);

   assert(loggerConfig.loggerName == name);
   assert(loggerConfig.logToStderr == true);
   assert(loggerConfig.stderrThreshold == Severity.fatal);
   assert(loggerConfig.logDirectory == "/tmp");
}

public struct LoggerConfig
{
   static string logToStderrFlag = "logtostderr";
   static string stderrThresholdFlag = "stderrthreshold";
   static string logDirectoryFlag = "logdir";

   static LoggerConfig create(ref string[] commandLine)
   {
      enforce(commandLine.length > 0);

      auto loggerConfig = LoggerConfig(commandLine[0]);

      getopt(commandLine,
             std.getopt.config.passThrough,
             logToStderrFlag, &loggerConfig._logToStderr,
             stderrThresholdFlag, &loggerConfig._stderrThreshold,
             logDirectoryFlag, &loggerConfig._logDirectory);

      return loggerConfig;
   }

   this(string loggerName)
   {
      _loggerName = loggerName;
      
      // get default log dir
      _logDirectory = getenv("LOGDIR");
      if(_logDirectory is null) _logDirectory = getenv("TEST_TMPDIR");
   }

   @property string loggerName() { return _loggerName; }

   @property void logToStderr(bool logToStderr) { _logToStderr = logToStderr; }
   @property bool logToStderr() { return _logToStderr; }

   @property void stderrThreshold(Severity stderrThreshold)
   {
      _stderrThreshold = stderrThreshold;
   }
   @property Severity stderrThreshold() { return _stderrThreshold; }

   @property void logDirectory(string logDirectory)
   {
      _logDirectory = logDirectory;
   }
   @property string logDirectory() { return _logDirectory; }

   @property void bufferSize(size_t bufferSize) { _bufferSize = bufferSize; }
   @property size_t bufferSize() { return _bufferSize; }


   private string _loggerName;
   private bool _logToStderr;
   private Severity _stderrThreshold = Severity.error;
   private string _logDirectory;
   private size_t _bufferSize = 4 * 1024;
}

/++
+/
class SharedLogger : Logger
{
   private this(LoggerConfig loggerConfig)
   {
      enforce(loggerConfig.loggerName);

      auto time = cast(DateTime) Clock.currTime();

      // Create file for every severity 
      static if(is(typeof(fatal) == NoopLogger)) enum staticWriters = 0;
      else static if(is(typeof(error) == NoopLogger)) enum staticWriters = 1;
      else static if(is(typeof(warning) == NoopLogger)) enum staticWriters = 2;
      else static if(is(typeof(info) == NoopLogger)) enum staticWriters = 3;
      else enum staticWriters = 4;

      // Add one more for stderr
      auto numberOfWriters = staticWriters == 0 ? 0 : staticWriters + 1;

      _writers = new File[numberOfWriters];
      if(_writers.length)
      {
         // add stderr if we are going to log
         assert(_writers.length > 1);
         _writers[$ - 1] = stderr;
      }

      // create the file name for all the writers
      foreach(severity; 0 .. numberOfWriters - 1)
      {
         _filenames ~= join(loggerConfig.logDirectory,
                            text(loggerConfig.loggerName,
                                 ".log.",
                                 severityNames[severity],
                                 ".",
                                 time.toISOString()));
      }
      _filenames ~= ""; // empty string represent stderr

      // create the indices for all the loggers
      _indices = new size_t[][staticWriters];
      foreach(i, ref index; _indices)
      {
         foreach(j; i .. staticWriters) index ~= j;
         if(loggerConfig.logToStderr && i <= loggerConfig.stderrThreshold)
         {
            index ~= _writers.length - 1;
         }
      }

      _mutex = new Mutex;
      _bufferSize = loggerConfig.bufferSize;
   }

   shared void log(const ref LogMessage message)
   {
      synchronized(_mutex)
      {
         foreach(i; _indices[message.severity]) 
         {
            if(!_writers[i].isOpen)
            {
               _writers[i].open(_filenames[i], "w");
               _writers[i].setvbuf(_bufferSize);
            }
            _writers[i].write(message.logLine());
         }
      }
   }

   shared void flush()
   {
      synchronized(_mutex)
      {
         foreach(ref writer; _writers[0 .. $ - 1])
         {
            if(writer.isOpen) writer.flush();
         }
      }
   }

   private size_t _bufferSize;
   private Mutex _mutex;
   private string[] _filenames;
   private size_t[][] _indices;
   __gshared File[] _writers;
}

unittest
{
   foreach(i; 0 .. 10) { if(every!5) assert(i % 5 == 0); }

   // different call site; should work again
   foreach(i; 0 .. 10) { if(every!2) assert(i % 2 == 0); }
}

/++
+/
bool every(uint times, string file = __FILE__, int line = __LINE__)()
{
   static if(times == 1) return true;
   else
   {
      static uint counter;
      if(++counter > times) counter -= times;

      return counter == 1;
   }
}

unittest
{
   foreach(i; 0 .. 10) { assert((first() && i == 0) || i != 0); }

   // different call site; should work again
   foreach(i; 0 .. 10) { assert((first!3 && i < 3) || i >= 3); }
}

/++
+/
bool first(uint times = 1, string file = __FILE__, int line = __LINE__)()
{
   static uint counter;
   if(++counter > times + 1) counter = times + 1;

   return counter <= times;
}

static this()
{
   if(is(typeof(fatal) == DefaultLogger))
   {
      fatal.init(Severity.fatal, &_moduleConfig);
   }

   if(is(typeof(error) == DefaultLogger))
   {
      error.init(Severity.error, &_moduleConfig);
   }

   if(is(typeof(warning) == DefaultLogger))
   {
      warning.init(Severity.warning, &_moduleConfig);
   }

   if(is(typeof(info) == DefaultLogger))
   {
      info.init(Severity.info, &_moduleConfig);
   }
}

private shared ModuleConfig _moduleConfig;
