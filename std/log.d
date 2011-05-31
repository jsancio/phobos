// Written in the D programming language.
// XXX Allow changing configuration after init. Remove FilterConfig and
//     VerboseConfig.
// XXX write unittest for SharedLogger
// XXX make sure that the examples are correct.
// XXX rename dfatal and vlog to debugFatal and verbose.

// TODO inspect all the try statements
// TODO remove the use of text!
// TODO Allow the configuration of the log file name
// TODO Allow the configuration of the log line

/++
Implements an application level logging mechanism.

---
import std.log;

void main()
{
   bool errorCond;

   info("Print this message", " when info severity is enabled.");
   error.when(errorCond)("Logs this error message when errorCond is true.");
   fatal.format("Calling %s will exit the process", to!string(Level.fatal));
   vlog(1)("Verbose level 1 message");
}
---

This module defines a set of functions useful for many common logging tasks.
The module allows the logging of messages at different severity levels and at
different verbose level. Log messages at different severity levels and verbose
level can be disabled and enabled both at compile time and at run time. The
module can also _log depending on user defined boolean conditions. The module
includes some commonly use conditions like $(D every) 'n' times and $(D first)
'n' times.

Four logging severity levels are defined - in other of severity they are:
$(D info), $(D warning), $(D error), $(D critical) and $(D fatal). Verbose
messages are logged using $(D vlog).

If the module is not initialized it will configure itself using the command
line arguments passed to the process and the process's enviroment variables.
For a list of command line option and enviroment variable, and their meaning
see $(D FilterConfig) and $(D LoggerConfig).

Example:
---
import std.log;

void main(string[] args)
{
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

      if(info.willLog)
      {
         auto message = "Cool message";
         // perform some complex operation
         // ...
         info(message);
      }

      vlog(2).when(first())("Verbose message only on the first iterations");
   }

   try critical("Critical message");
   catch(CriticalException e)
   {
      // shutdown application...
   }

   fatal("This is a fatal message!!!");
}
---

BUGS:
Not tested on Windows. Log messages do not contain the logging thread when
using vanilla druntime.
+/
module std.log;

import core.atomic : cas;
import core.thread : Thread;
import core.sync.mutex : Mutex;
import core.sync.rwmutex : ReadWriteMutex;
import core.runtime : Runtime;
import core.time : Duration;
import std.stdio : File, stderr, writefln;
import std.string : newline, toupper;
import std.conv : text, to;
import std.datetime: Clock, DateTime, SysTime;
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
   import core.time : dur;
}

version(StdDdoc)
{
   /++
      Fatal log messages terminate the application after the message is
      persisted. Fatal log message cannot be disabled at compile time or at
      run time.

      Example:
      ---
fatal("A fatal message!");
      ---
    +/
   LogFilter fatal;

   /++
      Debug fatal log messages log at fatal severity in debug mode and log at
      critical severity in release mode. See fatal and critical severity
      levels for a description of their behavior.

      Example:
      ---
dfatal("A fatal message in debug and an error message in release!");
      ---
    +/
   LogFilter dfatal;

   /++
      Critical log messages throw an exception after the message is persisted.
      Critical log messages cannot be disabled at compile time or at run time.

      Example:
      ---
critical("A critical message!");
      ---
    +/
   LogFilter critical;

   /++
      Error log messages are disabled at compiled time by setting the version
      to 'strip_log_error'. Error log messages are disabled at run time by
      setting the minimun severity to $(D Level.fatal) or $(D Level.critical)
      in $(D FilterConfig). Disabling _error log messages at compile time or
      at run time also disables lower severity messages, e.g. warning and
      info.

      Example:
      ---
error("An error message!");
      ---
    +/
   LogFilter error;

   /++
      Warning log messages are disabled at compiled time by setting the version
      to 'strip_log_warning'. Warning log messages are disabled at run time by
      setting the minimum severity to $(D Level.error) in $(D FilterConfig).
      Disabling _warning log messages at compile time or at run time also
      disables lower severity messages, e.g. info.

      Example:
      ---
warning("A warning message!");
      ---
    +/
   LogFilter warning;

   /++
      Info log messages are disabled at compiled time by setting the version to
      'strip_log_info'. Info log messages are disabled at run time by setting
      the minimum severity to $(D Level.warning) in $(D FilterConfig).
      Disabling _info log messages at compile time or at run time also disables
      verbose log messages.

      Example:
      ---
info("An info message!");
      ---
    +/
   LogFilter info;

   /++
      Verbose log messages are log at the info severity _level. To disable them
      at compile time set the version to 'strip_log_info' which also disables
      all messages of info severity at compile time. To enable verbose log
      messages at run time use the the maximum verbose _level property and the
      module filter property in $(D FilterConfig.VerboseConfig).

      Example:
      ---
vlog(1)("A verbose 1 message");
      ---
    +/
   LogFilter vlog(short level, string file = __FILE__);
}
else
{
   LogFilter fatal;
   LogFilter critical;

   version(strip_log_error) NoopLogFilter error;
   else typeof(fatal) error;

   version(strip_log_warning) NoopLogFilter warning;
   else typeof(error) warning;

   version(strip_log_info) NoopLogFilter info;
   else typeof(warning) info;

   debug alias fatal dfatal;
   else alias critical dfatal;

   ref typeof(info) vlog(short level, string file = __FILE__)
   {
      static if(is(typeof(return) == NoopLogFilter))
      {
         return info;
      }
      else
      {
         return LogFilter.vlog(level, _moduleConfig, info, file);
      }
   }
}

unittest
{
   LogFilter logInfo;
   LogFilter logWarning;
   LogFilter logError;
   LogFilter logCritical;
   LogFilter logFatal;

   auto testConfig = new ModuleConfig;

   // logger shouldn't log if not init
   assert(!logInfo.willLog);

   // logger shouldn't log if module configured
   logInfo.init(Severity.info, testConfig);
   assert(!logInfo.willLog);

   FilterConfig filterConfig;
   filterConfig.minSeverity = Severity.warning;

   auto logger = cast(shared) new SeverityFilter();
   filterConfig._logger = logger;

   testConfig.init(filterConfig);

   logWarning.init(Severity.warning, testConfig);
   logError.init(Severity.error, testConfig);
   logCritical.init(Severity.critical, testConfig);
   logFatal.init(Severity.fatal, testConfig);

   auto loggedMessage = "logged message";

   // Test willLog
   assert(!logInfo.willLog);
   assert(logWarning.willLog);
   assert(logError.willLog);
   assert(logCritical.willLog);
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
   try { logCritical(loggedMessage); assert(false); }
   catch (CriticalException e) {}
   assert(logger.called);
   assert(logger.severity == Severity.critical &&
          logger.message == loggedMessage);
   assert(logger.flushCalled);

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

/++
Conditionally records a log message by checking the severity level and any user
defined condition.

Examples:
---
error("Log an ", to!string(Level.error), " message!");
error.write("Log an ", to!string(Level.error), " message!");
error.format("Also logs an %s message!", to!string(Level.error));
---
Logs a message if the specified severity level is enabled.

---
void coolFunction(Object object)
{
   fatal.when(object is null)("I don't like null objects!");
   // ...
}

foreach(i; 0 .. 10)
{
   info.when(first())("Only log this the first time in the loop");
}
---
Logs a message if the specified severity level is enabled and all the user
defined condition are true.
+/
struct LogFilter
{
   private void init(Severity severity, ModuleConfig config)
   {
      _config = config;

      _message.severity = severity;
      // XXX remove this when druntime is fixed.
      static if(__traits(hasMember, Thread, "threadId"))
      {
         _message.threadId = Thread.getThis.threadId;
      }
   }

   /++
      Returns true when a message can be logged.

      Example:
      ---
if(error.willLog)
{
   string message;
   // Perform some compuration
   // ...
   error(message);
}
      ---
    +/
   @property bool willLog()
   {
      return _config !is null &&
             _message.severity <= _config.severity;
   }

   /++
      Returns this object if the parameter $(D now) evaluates to true and if a
      message can be logged. Note: The $(D now) parameter is only evaluated if
      a message can be logged with this object.

      Example:
      ---
foreach(i; 0 .. 10)
{
   warning.when(i == 9)("Executed loop when i = 9");
   // ...
}
      ---
    +/
   ref LogFilter when(lazy bool now)
   {
      if(willLog && now) return this;

      return _noopLogFilter;
   }

   /++
      Concatenates all the arguements and logs them. Note: The parameters are
      only evaluated if a message can be logged.

      Example:
      ---
auto pi = 3.14159265;

info.write("The value of pi is ", pi);

// The same as above...
info("The value of pi is ", pi);
      ---
    +/
   void write(string file = __FILE__, int line = __LINE__, T...)(lazy T args)
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
   alias write opCall; /// ditto

   /++
      Formats the parameters $(D args) given the _format string $(D fmt) and
      logs them. Note: The parameters are only evaluated if a message can be
      logged. For a description of the _format string see
      $(D std._format.formattedWrite).

      Example:
      ---
auto goldenRatio = 1.61803399;

vlog(1).format("The number %s is the golden ratio", goldenRatio);
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
      _writer.clear();
      foreach(T, arg; args) _writer.put(to!(char[])(arg));
      message.message = _writer.data;

      // record the time stamp
      message.time = Clock.currTime;

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
         else if(message.severity == Severity.critical)
         {
            _config.logger.flush();
            throw new CriticalException(message.message.idup);
         }
      }

      _config.logger.log(message);
   }

   private void logf(T...)(ref Logger.LogMessage message, string fmt, T args)
   {
      assert(willLog);

      // record message
      _writer.clear();
      _writer.reserve(fmt.length);
      formattedWrite(_writer, fmt, args);
      message.message = _writer.data;

      // record the time stamp
      message.time = Clock.currTime;

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
         else if(message.severity == Severity.critical)
         {
            _config.logger.flush();
            throw new CriticalException(message.message.idup);
         }
      }

      _config.logger.log(message);
   }

   unittest
   {
      auto loggedMessage = "Verbose log message";

      LogFilter logInfo;
      LogFilter logWarning;
      auto testConfig = new ModuleConfig;

      logInfo.init(Severity.info, testConfig);
      logWarning.init(Severity.warning, testConfig);

      // verbose logging shouldn't throw if module not init
      auto verboseLog = LogFilter.vlog(0, testConfig, logWarning);
      assert(!verboseLog.willLog);

      FilterConfig filterConfig;
      filterConfig.minSeverity = Severity.warning;
      filterConfig.verboseConfig.maxVerboseLevel = 3;
      filterConfig.verboseConfig.moduleFilter = "*log.d=2";

      auto logger = cast(shared) new SeverityFilter();
      filterConfig._logger = logger;

      testConfig.init(filterConfig);

      // Test vlogging and module filtering
      logger.clear();
      verboseLog = LogFilter.vlog(2, testConfig, logWarning);
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
      verboseLog = LogFilter.vlog(3, testConfig, logWarning);
      verboseLog(loggedMessage);
      assert(!logger.called);

      // test wrong module
      logger.clear();
      verboseLog = LogFilter.vlog(4, testConfig, logWarning, "not_this");
      verboseLog.format("%s", loggedMessage);
      assert(!logger.called);

      // test verbose level
      logger.clear();
      verboseLog = LogFilter.vlog(3, testConfig, logWarning, "not_this");
      verboseLog.format("%s", loggedMessage);
      assert(logger.called);
      assert(logger.severity == Severity.warning &&
            logger.message == loggedMessage);

      // test severity config too high
      logger.clear();
      verboseLog = LogFilter.vlog(2, testConfig, logInfo);
      assert(!verboseLog.willLog);
      verboseLog.format("%s", loggedMessage);
      assert(!logger.called);
   }

   private static ref LogFilter vlog(short level,
                                     ModuleConfig config,
                                     ref LogFilter logger,
                                     string file = __FILE__)
   {
      if(logger.willLog && config.matchesVerboseConfig(file, level))
      {
         return logger;
      }

      return _noopLogFilter;
   }

   private Logger.LogMessage _message;
   private Appender!(char[]) _writer;

   private ModuleConfig _config;

   private static __gshared LogFilter _noopLogFilter;
}

final class CriticalException : Exception
{
   private this(string message,
        string file = __FILE__,
        int line = __LINE__)
   {
      super(message, null, file, line);
   }
}

unittest
{
   // test that both LogFilter and NoopLogFilter same public methods
   void publicInterface(T)()
   {
      T filter;
      if(filter.willLog) {}

      filter.write("hello ", 1, " world");
      filter(1, " hello world");
      filter.format("format string", true, 4, 5.0);
      filter.when(true)("message");
   }

   assert(__traits(compiles, publicInterface!LogFilter()));
   assert(__traits(compiles, publicInterface!NoopLogFilter()));
}

// Used by the module to disable logging at compile time.
struct NoopLogFilter
{
   @property bool willLog() const { return false; }

   ref NoopLogFilter when(lazy bool now) { return this; }
   void write(T...)(lazy T args) {}
   alias write opCall;
   void format(T...)(lazy string fmt, lazy T args) {}
}

/// Defines the severity levels supported by the logging library.
enum Severity
{
   fatal = 0, ///
   critical, /// ditto
   error, /// ditto
   warning, /// ditto
   info /// ditto
}

unittest
{
   // assert default values
   FilterConfig filterConfig;
   assert(filterConfig._minSeverity == Severity.error);

   auto name = "program_name";
   auto args = [name,
                "--" ~ FilterConfig.minSeverityFlag,
                "info",
                "--" ~ FilterConfig.VerboseConfig.moduleFilterFlag,
                "*logging=2,module=0",
                "--" ~ FilterConfig.VerboseConfig.maxVerboseLevelFlag,
                "3",
                "--ignoredOption"];

   filterConfig = FilterConfig.create(args);

   // assert that all expected options where removed
   assert(args.length == 2);
   assert(args[0] == name);

   assert(filterConfig._minSeverity == Severity.info);

   // assert max verbose level
   assert(filterConfig._verboseConfig.matches("file", 3));

   // assert vmodule entries
   assert(filterConfig._verboseConfig.matches("std/logging.d", 2));
   assert(filterConfig._verboseConfig.matches("module.d", 0));
}

/++
Module configuration structure.

This object is used to configure the logging module if the default behavior is
not wanted.
+/
struct FilterConfig
{
   /++
      Create a configuration object based on the passed parameter.

      The function processes every entry in commandLine looking for valid
      command line options. All of the valid options are enumerated in the
      static fields of this structure that end in 'Flag', e.g. minSeverityFlag.
      When a valid command line option is found its value is stored in the
      mapping object's property. For any property not set explictly its default
      value is used. Here is a list of all the flags and how they map to the
      object's property:

      $(UL
         $(LI $(D minSeverityFlag) maps to $(D minSeverity)))

      Any valid field is removed from commandLine; any invalid field is left in
      commandLine.

      After processing all the flags beloging to FilterConfig the remaining
      arguments are passed to $(D FilterConfig.VerboseConfig) for processing.
    +/
   static FilterConfig create(ref string[] commandLine)
   {
      FilterConfig filterConfig;

      getopt(commandLine,
             std.getopt.config.passThrough,
             minSeverityFlag, &filterConfig._minSeverity);

      filterConfig._verboseConfig = VerboseConfig.create(commandLine);

      return filterConfig;
   }

   /++
      Command line flag for setting the minimum severity level. The default
      value is "minloglevel" which at the command line is '--minloglevel'.
    +/
   static string minSeverityFlag = "minloglevel";

   /++
      Specifies the minimum _severity of the messages that are logged.

      Only messages with a _severity greater than or equal to the value of this
      property are logged.

      The default value is $(D Severity.error).
    +/
   @property void minSeverity(Severity severity)
   {
      _minSeverity = severity;
   }

   /++
      Returns the $(D FilterConfig.VerboseConfig) enclosed by this object.
    +/
   @property ref VerboseConfig verboseConfig()
   {
      return _verboseConfig;
   }

   /++
      Function pointer for handling log message with a severity of fatal.

      This function is called by the thread trying to log a fatal message. The
      function handler should not return; otherwise the framework calls
      $(D assert(false)).

      The default value is $(D null).
    +/
   @property void fatalHandler(void function() handler)
   {
      _fatalHandler = handler;
   }

   unittest
   {
      auto vmodule = "module=1,*another=3,even*=2,cat?=4,*dog?=1,evenmore=10";
      VerboseConfig result;
      result.moduleFilter = vmodule;

      // Test exact patterns
      assert(result.matches("module", 1));
      assert(result.matches("module.d", 1));
      assert(!result.matches("amodule", 1));

      // Test *
      assert(result.matches("package/another", 3));
      assert(result.matches("package/another.d", 3));
      assert(!result.matches("package/dontknow", 3));

      assert(result.matches("evenmore", 2));
      assert(result.matches("evenmore.d", 2));
      assert(!result.matches("package/evenmore.d", 2));

      // Test ?
      assert(result.matches("cats.d", 4));
      assert(!result.matches("cat", 4));

      // Test * and ?
      assert(result.matches("package/dogs.d", 1));
      assert(!result.matches("package/doggies.d", 1));
      assert(!result.matches("package/horse", 1));

      // Test that it can match any of the entries
      assert(result.matches("evenmore.d", 10));

      // Test invalid strings
      try { result.moduleFilter = "module=2,"; assert(false); }
      catch (Exception e) {}

      try { result.moduleFilter = "module=a"; assert(false); }
      catch (Exception e) {}

      try { result.moduleFilter = "module=2,another="; assert(false); }
      catch (Exception e) {}

      // Test max verbose level
      result.moduleFilter = null;
      result.maxVerboseLevel = 1;
      assert(result.matches("file", 1));
      assert(result.matches("file", 0));
      assert(!result.matches("file", 2));
   }

   /++
      Structure for configuring verbose logging.

      This structure is used to control verbose logging globally or  on a per
      module basis.
    +/
   struct VerboseConfig
   {
      /++
         Create a configuration object based on the passed parameter.

         The function processes every entry in commandLine looking for valid
         command line options. All of the valid options are enumerated in the
         static fields of this structure that end in 'Flag', e.g.
         maxVerboseLevelFlag. When a valid command line option is found its
         value is stored in the mapping object's property. For any property not
         set explictly its default value is used. Here is a list of all the
         flags and how they map to the object's property:

         $(UL
            $(LI $(D moduleFilterFlag) maps to $(D moduleFilter))
            $(LI $(D maxVerboseLevelFlag) maps to $(D maxVerboseLevel)))

         Any valid field is removed from commandLine; any invalid field is left
         in commandLine.
       +/
      static VerboseConfig create(ref string[] commandLine)
      {
         VerboseConfig result;

         void vmodule(string option, string value)
         {
            result.moduleFilter = value;
         }

         getopt(commandLine,
               std.getopt.config.passThrough,
               moduleFilterFlag, &vmodule,
               maxVerboseLevelFlag, &result._level);


         return result;
      }

      /++
         Command line flag for setting the verbose configuration per module.
         The default value is "vmodule" which at the command line is
         '--vmodule'.
       +/
      static string moduleFilterFlag = "vmodule";

      /++
         Command line flag for setting the maximum verbose level. The default
         value is "v" which at the command line is '--v'.
       +/
      static string maxVerboseLevelFlag = "v";

      /++
         Specifies the maximum verbose _level of verbose messages that can
         logged.

         Verbose messages with a verbose _level less than or equal to the
         value of this property are logged. This property is ignore of the
         module logging the verbose message matches a module specified in the
         verbose configuration for modules property.

         The default value is $(D short.min).
       +/
      @property void maxVerboseLevel(short level)
      {
         _level = level;
      }

      /++
         Specifies the verbose configuration for modules.

         A verbose message with level $(D x) is get logged at severity level
         info if there is an entry that matches to the source file and the
         verbose level of that entry is greater than or equal to $(D x).

         The format of the configuration string is as follow
         "[pattern]=[level],...", where '[pattern]' may contain any character
         allowed in a file name and '[level]' is convertible to an integer.
         Every '*' in '[pattern]' matches any number of characters.
         Every '?' in '[pattern]' matches exactly one character.

         For every '[pattern]=[level]' in the configuration string an entry is
         created.

         Example:
         ---
FilterConfig.VerboseConfig config;
config.moduleFilter = "module=2,great*=3,*test=1";
         ---

         The code above sets a verbose logging configuration that:
         $(UL
            $(LI Log verbose 2 and lower messages from 'module{,.d}')
            $(LI Log verbose 3 and lower messages from anyting starting with
                 'great')
            $(LI Log verbose 1 and lower messages from any file that ends with
                 'test{,.d}'))

         Note: If the module trying to log a verbose message matches but the
         verbose level don't match, then the maximum verbose level property is
         ignored.

         E.g. In the default configuration if the command line contains "--v=2
         --vmodule=web=1".
         ---
module web;

// ...

vlog(2)("Verbose message is not logged");
         ---

         The verbose message is not logged even though it is less than or equal
         to 2, as specified in the command line.

         The default value is $(D null).
       +/
      @property void moduleFilter(string config)
      {
         typeof(_modulePatterns) patterns;
         typeof(_moduleLevels) levels;

         foreach(entry; splitter(config, ","))
         {
            enforce(entry != "");

            auto entryParts = array(splitter(entry, "="));
            enforce(entryParts.length == 2);
            enforce(entryParts[0] != "");

            string altName;
            if(!endsWith(entryParts[0], ".d"))
            {
               altName = entryParts[0] ~ ".d";
            }

            patterns ~= [ entryParts[0], altName ];
            levels ~= to!short(entryParts[1]);
         }
         assert(patterns.length == levels.length);

         _modulePatterns = patterns;
         _moduleLevels = levels;
      }

      this(this)
      {
         _modulePatterns = _modulePatterns.dup;
         _moduleLevels = _moduleLevels.dup;
      }

      ref VerboseConfig opAssign(VerboseConfig config)
      {
         swap(this, config);
         return this;
      }

      private bool matches(string file, short level) const
      {
         assert(_modulePatterns.length == _moduleLevels.length);

         bool matchedFile;
         foreach(i; 0 .. _modulePatterns.length)
         {
            foreach(pattern; _modulePatterns[i])
            {
               if(fnmatch(file, pattern))
               {
                  if(level <= _moduleLevels[i]) return true;

                  matchedFile = true;
               }
            }
         }

         return !matchedFile && level <= _level;
      }

      private short _level = short.min;
      private string[2][] _modulePatterns;
      private short[] _moduleLevels;
   }

   private Severity _minSeverity = Severity.error;
   private VerboseConfig _verboseConfig;
   private void function() _fatalHandler;
   private shared Logger _logger;
}

unittest
{
   auto name = "program_name";
   // assert default values
   auto loggerConfig = LoggerConfig(name);
   assert(loggerConfig.loggerName == name);
   assert(loggerConfig.logToStderr == false);
   assert(loggerConfig.alsoLogToStderr == false);
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
   assert(loggerConfig.logToStderr);
   assert(!loggerConfig.alsoLogToStderr);
   assert(loggerConfig.stderrThreshold == Severity.fatal);
   assert(loggerConfig.logDirectory == "/tmp");

   // test alsoLogToStderr
   args = [name, "--" ~ LoggerConfig.alsoLogToStderrFlag];

   loggerConfig = LoggerConfig.create(args);
   assert(loggerConfig.alsoLogToStderr);
}

/++
Structure for configuring the default backend logger.
+/
public struct LoggerConfig
{
   /++
      Create a configuration object based on the passed parameter.

      The function processes every entry in commandLine looking for valid
      command line options. All of the valid options are enumerated in the
      static fields of this structure that end in 'Flag', e.g. logToStderrFlag.
      When a valid command line option is found its value is stored in the
      mapping object's property. For any property not set explictly its default
      value is used. Here is a list of all the flags and how they map to
      the object's property:

      $(UL
            $(LI $(D logToStderrFlag) maps to $(D logToStderr))
            $(LI $(D alsoLogToStderrFlag) maps to $(D alsoLogToStderr))
            $(LI $(D stderrThresholdFlag) maps to $(D stderrThreshold))
            $(LI $(D logDirectoryFlag) maps to $(D logDirectory)))

      Any valid field is removed from commandLine; any invalid field is left in
      commandLine.

      The loggerName property is set to the program name, i.e. the first
      element of commandLine.
    +/
   static LoggerConfig create(ref string[] commandLine)
   {
      enforce(commandLine.length > 0);

      auto loggerConfig = LoggerConfig(commandLine[0]);

      getopt(commandLine,
             std.getopt.config.passThrough,
             logToStderrFlag, &loggerConfig._logToStderr,
             alsoLogToStderrFlag, &loggerConfig._alsoLogToStderr,
             stderrThresholdFlag, &loggerConfig._stderrThreshold,
             logDirectoryFlag, &loggerConfig._logDirectory);

      return loggerConfig;
   }

   /++
      Command line flag for logging to stderr. The default value is
      "logtostderr" which at the command line is '--logtostderr'.
    +/
   static string logToStderrFlag = "logtostderr";

   /++
      Command line flag for logging to stderr and files. The default value is
      "alsologtostderr" which at the command line is '--alsologtostderr'.
    +/
   static string alsoLogToStderrFlag = "alsologtostderr";

   /++
      Command line flag for setting the stderr logging threshold. The default
      value is "stderrthreshold" which at the command line is
      '--stderrthreshold'.
    +/
   static string stderrThresholdFlag = "stderrthreshold";

   /++
      Command line flag for setting the logging directory. The default value is
      "logdir" which at the command line is '--logdir'.
    +/
   static string logDirectoryFlag = "logdir";

   /++
      Constructor that sets the property $(D loggerName) to name.
    +/
   this(string name)
   {
      _loggerName = name;

      // get default log dir
      _logDirectory = getenv("LOGDIR");
      if(_logDirectory is null) _logDirectory = getenv("TEST_TMPDIR");
   }

   /// Name to use when generating log file names.
   @property const string loggerName() { return _loggerName; }

   /++
      Specifies if the logger should write to stderr. If this property is set,
      then it only logs to stderr and not to files.

      The default value is false.
    +/
   @property void logToStderr(bool logToStderr) { _logToStderr = logToStderr; }
   @property const bool logToStderr() { return _logToStderr; } /// ditto

   /++
      Specifies if the logger should write to stderr. If this property is set,
      then it logs to stderr and to files.

      The default value is false.
    +/
   @property void alsoLogToStderr(bool alsoLogToStderr)
   {
      _alsoLogToStderr = alsoLogToStderr;
   }
   @property const bool alsoLogToStderr() { return _alsoLogToStderr; } /// ditto

   /++
      Specifies the _threshold at which log messages are logged to stderr. Any
      message of higher or equal severity to threshold is written to stderr.

      The default value is $(D Severity.error).
    +/
   @property void stderrThreshold(Severity threshold)
   {
      _stderrThreshold = threshold;
   }
   /// ditto
   @property const Severity stderrThreshold()
   {
      return _stderrThreshold;
   }

   /++
      Specifies the directory where log files are created.

      The default value for this property is the value in the enviroment
      variable 'LOGDIR'. If 'LOGDIR' is not set, then 'TEST_TMPDIR' is used. If
      'TEST_TMPDIR' is not set, then it logs to the current directory.
    +/
   @property void logDirectory(string logDirectory)
   {
      _logDirectory = logDirectory;
   }
   @property const string logDirectory() { return _logDirectory; } /// ditto

   /++
      Specifies the buffer size for each log file.

      The default value is 4KB.
    +/
   @property void bufferSize(size_t bufferSize) { _bufferSize = bufferSize; }
   @property const size_t bufferSize() { return _bufferSize; } /// ditto

   private string _loggerName;
   private bool _logToStderr;
   private bool _alsoLogToStderr;
   private Severity _stderrThreshold = Severity.error;
   private string _logDirectory;
   private size_t _bufferSize = 4 * 1024;
}

/++
Initialize the logging infrastructure.

A call to the function is not required if the module will be initialized using
the command line's default options. It throws an exception if called after a
logging call has been made.

This function treats the parameter commandLine as the command line arguments to
this process. Every valid option to this module will be removed from
commandLine. For list of all the supported command line options see
$(D FilterConfig) and $(D LoggerConfig).

Example:
---
import std.log;

void main(string[] args)
{
   initLogging(args);
   // ...
}
---
+/
void initLogging(T : Logger = SharedLogger, LC = LoggerConfig)
                (ref string[] commandLine)
{
   initLogging!T(LC.create(commandLine), FilterConfig.create(commandLine));
}

/++
Initialize the logging infrastructure.

A call to the function is not required if the module will be initialized using
the command line's default options. It throws an exception if called after a
logging call has been made.

This function allows the caller to change and configure the the backend logger
to a different $(D Logger).

Params:
   T = The type of the $(D Logger) to instanciate.
   loggerConfig = The configuration object used by the logger. It will be
                  passed to $(D T)'s constructor.
   filterConfig = The configuration object used by $(D std.log).

Example:
---
import std.log;

class NullLogger : Logger
{
   this(LoggerConfig config) {}
   shared void log(const ref LogMessage message) {}
   shared void flush() {}
}

void main(string[] args)
{
   initializeLogging!NullLogger(LoggerConfig.create(args),
                                FilterConfig.create(args));
   // ...
}
---
This example disables writing log messages at run time.
+/
void initLogging(T : Logger, LC)
                (LC loggerConfig, FilterConfig filterConfig = FilterConfig())
{
   filterConfig._logger = cast(shared) new T(loggerConfig);
   _moduleConfig.init(filterConfig);
}

/++
Extension point for the module.
+/
interface Logger
{
/++
Logs a _message.

The method is called by $(D std._log) whenever it decides that a _message
should be logged. It is not required that the implementation of this method do
any filtering based on severity since at this point all configured filters were
performed.

The method is allow to return immediately without persisting the _message.
+/
   shared void log(const ref LogMessage message);

/++
Flushes pending log operations.

The method is called by $(D std.log) whenever it requires the persistence of
all the previous messages. For example the method is called when the client
logs a fatal message.

The method must not return until all pending log operations complete.
+/
   shared void flush();

   /++
      Log message constructed by $(D std.log) and passed to $(D Logger) for
      recording.
    +/
   public static struct LogMessage
   {
      /// Name of source file that created the log message.
      string file;

      /// Line number in the source file that created the log message.
      int line;

      /// Severity of the log message.
      Severity severity;

      /// Thread that created that the log message.
      int threadId;

      /// User defined message.
      char[] message;

      /// Time when the log message was created.
      SysTime time;
   }
}

/++
Default $(D Logger) implementation.

This logger implements all the configuration option described in
$(D LoggerConfig). This logger writes log messages to multiple files. There is
a file for every severity level. Log messages of a given severity are written
to all the log files of an equal or lower severity. E.g. A log message of
severity warning will be written to the log files for warning and info but not
to the log files of fatal and error.
+/
class SharedLogger : Logger
{
   /++
      Constructs a logger with the configuration specified in loggerConfig.

      This constructor is required by $(D initializeLogging).
    +/
   private this(const ref LoggerConfig loggerConfig)
   {
      enforce(loggerConfig.loggerName);

      _loggerConfig = loggerConfig;
      _mutex = new Mutex;

      // Create file for every severity
      enum logFilters = numberOfLogFilters();

      // Add one more for stderr
      auto numberOfWriters = logFilters == 0 ? 0 : logFilters + 1;

      _writers = new File[numberOfWriters];

      // create the indices for all the loggers
      _indices = new size_t[][logFilters];
      foreach(i, ref index; _indices)
      {
         if(_loggerConfig.logToStderr)
         {
            // Only log to stderr
            if(i <= _loggerConfig.stderrThreshold) index ~= _writers.length - 1;
         }
         else
         {
            // Add the file writers
            foreach(j; i .. logFilters) index ~= j;

            // Add stderr if needed
            if(_loggerConfig.alsoLogToStderr &&
               i <= _loggerConfig.stderrThreshold)
            {
               index ~= _writers.length - 1;
            }
         }
      }
   }

   private static int numberOfLogFilters() pure nothrow
   {
      static if(is(typeof(fatal) == NoopLogFilter)) return 0;
      else static if(is(typeof(critical) == NoopLogFilter)) return  1;
      else static if(is(typeof(error) == NoopLogFilter)) return  2;
      else static if(is(typeof(warning) == NoopLogFilter)) return 3;
      else static if(is(typeof(info) == NoopLogFilter)) return 4;
      else return 5;
   }

   private shared void init()
   {
      if(_initialized) return;

      scope(success) _initialized = true;

      auto time = cast(DateTime) Clock.currTime();

      // Add stderr
      if(_writers.length)
      {
         // add stderr if we are going to log
         assert(_writers.length > 1);
         _writers[$ - 1] = stderr;
      }

      // create the file name for all the writers
      foreach(severity; 0 .. _writers.length - 1)
      {
         _filenames ~= join(_loggerConfig.logDirectory,
                            text(_loggerConfig.loggerName,
                                 ".log.",
                                 toupper(to!string(cast(Severity)severity)),
                                 ".",
                                 time.toISOString()));
      }
      _filenames ~= ""; // empty string represent stderr
   }

   /// Writes a _log message to all the _log files of equal or lower severity.
   shared void log(const ref LogMessage message)
   {
      synchronized(_mutex)
      {
         init();
         foreach(i; _indices[message.severity])
         {
            if(!_writers[i].isOpen)
            {
               _writers[i].open(_filenames[i], "w");
               _writers[i].setvbuf(_loggerConfig.bufferSize);
            }
            _writers[i].writefln("%s:%s:%s:%x:%s %s",
                                 message.file,
                                 message.line,
                                 toupper(to!string(message.severity)),
                                 message.threadId,
                                 message.time.toISOString(),
                                 message.message);
         }
      }
   }

   /// Flushes the buffer of all the log files.
   shared void flush()
   {
      synchronized(_mutex)
      {
         init();
         foreach(ref writer; _writers[0 .. $ - 1])
         {
            if(writer.isOpen) writer.flush();
         }
      }
   }

   private __gshared LoggerConfig _loggerConfig;
   private bool _initialized;

   private Mutex _mutex; // rwmutex wont preserve the order
   private string[] _filenames;
   private size_t[][] _indices;
   __gshared File[] _writers;
}

unittest
{
   foreach(i; 0 .. 10) { if(every(5)) assert(i % 5 == 0); }

   // different call site; should work again
   foreach(i; 0 .. 10) { if(every(2)) assert(i % 2 == 0); }

   foreach(i; 0 .. 3)
   {
      if(every(dur!"msecs"(40))) assert(i == 0 || i == 2);
      Thread.sleep(dur!"msecs"(21));
   }
}

/++
The first version of this function returns true once _every n times it is called
at a specific call site; otherwise it returns false.

The second version of this function return true only after n unit of time as
after the previous call from a specific call site; otherwise it returns false.

Example:
---
auto firstCounter = 0;
auto secondCounter = 0;

foreach(i; 0 .. 10)
{
   if(every(2)) ++firstCounter;

   if(every(3)) ++secondCounter;
}
assert(firstCounter == 5);
assert(secondCounter == 4);
---
The code above executes without asserting.
+/
bool every(string file = __FILE__, int line = __LINE__)(uint n)
{
   static uint counter;
   if(++counter > n) counter -= n;

   return counter == 1;
}
/// ditto
bool every(string file = __FILE__, int line = __LINE__)(Duration n)
{
   static long lastTime;
   auto currentTime = Clock.currTime.stdTime;

   if(lastTime == 0 || currentTime - lastTime >= n.total!"hnsecs")
   {
      lastTime = currentTime;
      return true;
   }

   return false;
}

unittest
{
   foreach(i; 0 .. 10) { assert((first() && i == 0) || i != 0); }

   // different call site; should work again
   foreach(i; 0 .. 10) { assert((first(3) && i < 3) || i >= 3); }

   foreach(i; 0 .. 3)
   {
      if(first(dur!"msecs"(40))) assert(i == 0 || i == 1);
      Thread.sleep(dur!"msecs"(21));
   }
}

/++
The _first version of this function returns true the _first n times it is called
at a specific call site; otherwise it returns false.

The second version of this function returns true every time it is called in the
_first n unit of time at a specific call site; otherwise it returns false.

Example:
---
auto firstCounter = 0;
auto secondCounter = 0;

foreach(i; 0 .. 10)
{
   if(first(2)) firstCounter += i;

   if(first(3)) secondCounter += i;
}
assert(firstCounter == 1); // 0 + 1
assert(secondCounter == 3); // 0 + 1 + 2
---
The code above executes without asserting.
+/
bool first(string file = __FILE__, int line = __LINE__)(uint n = 1)
{
   static uint counter;

   if(counter >= n) return false;
   ++counter;

   return true;
}
/// ditto
bool first(string file = __FILE__, int line = __LINE__)(Duration n)
{
   static long firstTime;
   static bool expired;

   firstTime = firstTime ? firstTime : Clock.currTime.stdTime;

   /* we don't support the value of n changing; once false it will always be
    * false
    */
   if(expired) return false;

   auto currentTime = Clock.currTime.stdTime;
   if(currentTime - firstTime >= n.total!"hnsecs")
   {
      expired = true;
      return false;
   }

   return true;
}

unittest
{
   foreach(i; 0 .. 10) { assert((after(9) && i == 9) || i != 9); }

   // different call site; should work again
   foreach(i; 0 .. 10) { assert((after(7) && i >= 7) || i < 7); }

   foreach(i; 0 .. 3)
   {
      if(after(dur!"msecs"(40))) assert(i == 2);
      Thread.sleep(dur!"msecs"(21));
   }
}

/++
The first version of this function returns true _after it is called n time at a
specific call site.

The second version of this function returns true _after n unit of time has
passed since the first call at a specific call site.

Example:
---
auto firstCounter = 0;
auto secondCounter = 0;

foreach(i; 0 .. 10)
{
   if(after(8)) firstCounter += i;

   if(after(7)) secondCounter += i;
}
assert(firstCounter == 17); // 8 + 9
assert(secondCounter == 24); // 7 + 8 + 9
---
The code above executes without asserting.
+/
bool after(string file = __FILE__, int line = __LINE__)(uint n)
{
   static uint counter;

   if(counter >= n) return true;
   ++counter;

   return false;
}
/// ditto
bool after(string file = __FILE__, int line = __LINE__)(Duration n)
{
   static long firstTime;
   static bool expired;

   firstTime = firstTime ? firstTime : Clock.currTime.stdTime;

   // we don't support the value of n changing; once true will always be true
   if(expired) return true;

   auto currentTime = Clock.currTime.stdTime;
   if(currentTime - firstTime >= n.total!"hnsecs")
   {
      return expired = true;
   }

   return false;
}

unittest
{
}

private final class ModuleConfig
{
   this()
   {
      _rwmutex = new ReadWriteMutex(ReadWriteMutex.Policy.PREFER_READERS);
   }

   void init(FilterConfig filterConfig)
   {
      enforce(filterConfig._logger);

      // there should really be no readers while the trying to init
      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;

      // it is a error if the user tries to init after the logger has been used
      enforce(!_loggerUsed);

      _verboseConfig = filterConfig._verboseConfig;

      _logger = filterConfig._logger;

      _severity = filterConfig._minSeverity;
      // cannot disable critical severity
      _severity = _severity < Severity.critical ?
                              Severity.critical :
                              _severity;

      _fatalHandler =  filterConfig._fatalHandler ?
                       filterConfig._fatalHandler :
                       function {};
   }

   @property shared(Logger) logger()
   {
      synchronized(_rwmutex.reader)
      {
         // Somebody asked for the logger don't allow changing it
         _loggerUsed = true;
         return _logger;
      }
   }

   @property Severity severity()
   {
      synchronized(_rwmutex.reader())
      {
         return _severity;
      }
   }

   bool matchesVerboseConfig(string file, short level)
   {
      synchronized(_rwmutex.reader)
      {
         return _verboseConfig.matches(file, level);
      }
   }

   @property void function() fatalHandler()
   {
      synchronized(_rwmutex.reader)
      {
         return _fatalHandler;
      }
   }

   private bool _loggerUsed;
   private shared Logger _logger;
   private Severity _severity;
   private FilterConfig.VerboseConfig _verboseConfig;
   private void function() _fatalHandler;
   private ReadWriteMutex _rwmutex;
}

static this()
{
   fatal.init(Severity.fatal, _moduleConfig);
   critical.init(Severity.critical, _moduleConfig);

   if(is(typeof(error) == LogFilter))
   {
      error.init(Severity.error, _moduleConfig);
   }

   if(is(typeof(warning) == LogFilter))
   {
      warning.init(Severity.warning, _moduleConfig);
   }

   if(is(typeof(info) == LogFilter))
   {
      info.init(Severity.info, _moduleConfig);
   }
}

shared static this()
{
   _moduleConfig = new ModuleConfig;

   // XXX should try and catch this...
   auto args = Runtime.args;
   initLogging(args);
}

private __gshared ModuleConfig _moduleConfig;

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
