// Written in the D programming language.
// XXX rename LogFilter
// XXX test changing Flag in parseCommandLine for FileLogger.Configuration
// XXX test failure in parseCommandLine for FileLogger.Configuration
// XXX make sure that the examples are correct.

/++
Implements an application level logging mechanism.

---
import std.log;

void main()
{
   bool errorCond;

   log!info("Print this message", " when info severity is enabled.");
   log!error.when(errorCond)("Logs this error message when errorCond is true.");
   log!fatal.format("Calling %s will exit the process", to!string(Level.fatal));
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
see $(D Configuration) and $(D FileLogger.Configuration).

Example:
---
import std.log;

void main(string[] args)
{
   log!info.format("You passed %s argument(s)", args.length - 1);
   log!info.when(args.length > 1)("Arguments: ", args[1 .. $]);

   log!info("This is an info message.");
   log!warning("This is a warning message.");
   log!error("This is an error message!");
   log!dfatal("This is a debug fatal message");

   vlog(0)("Verbosity 0 message");
   vlog(1)("Verbosity 1 message");
   vlog(2)("Verbosity 2 message");

   foreach (i; 0 .. 10)
   {
      log!info.when(every(9))("Every nine");

      if(log!info.willLog)
      {
         auto message = "Cool message";
         // perform some complex operation
         // ...
         log!info(message);
      }

      vlog(2).when(first())("Verbose message only on the first iterations");
   }

   try log!critical("Critical message");
   catch(CriticalException e)
   {
      // shutdown application...
   }

   log!fatal("This is a fatal message!!!");
}
---

BUGS:
Not tested on Windows. Log messages do not contain the logging thread when
using vanilla druntime.

Copyright: Jose Armando Garcia Sancio 2011-.

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Jose Armando Garcia Sancio

Source: $(PHOBOSSRC std/_log.d)
+/
module std.log;

import core.thread;
import core.sync.mutex;
import core.sync.rwmutex;
import core.runtime;
import core.time;
import std.stdio;
import std.string;
import std.conv;
import std.datetime;
import std.exception;
import std.getopt;
import std.process;
import std.array;
import std.format;
import std.path;
import std.algorithm;
import std.functional;
import std.file;

version(Posix)
{
   import core.sys.posix.unistd;
   import core.sys.posix.sys.utsname;
}

version(unittest) import core.exception;

/++
Fatal log messages terminate the application after the message is persisted.
Fatal log message cannot be disabled at compile time or at run time.

Example:
---
log!fatal("A fatal message!");
---
+/
alias Severity.fatal fatal;

/++
Debug fatal log messages log at fatal severity in debug mode and log at
critical severity in release mode. See fatal and critical severity levels for
a description of their behavior.

Example:
---
log!dfatal("A fatal message in debug and an error message in release!");
---
+/
debug alias Severity.fatal dfatal;
else alias Severity.critical dfatal;

/++
Critical log messages throw an exception after the message is persisted.
Critical log messages cannot be disabled at compile time or at run time.

Example:
---
log!critical("A critical message!");
---
+/
alias Severity.critical critical;

/++
Error log messages are disabled at compiled time by setting the version to
'strip_log_error'. Error log messages are disabled at run time by setting the
minimun severity to $(D Level.fatal) or $(D Level.critical) in
$(D Configuration). Disabling _error log messages at compile time or at run
time also disables lower severity messages, e.g. warning and info.

Example:
---
log!error("An error message!");
---
+/
alias Severity.error error;

/++
Warning log messages are disabled at compiled time by setting the version to
'strip_log_warning'. Warning log messages are disabled at run time by setting
the minimum severity to $(D Level.error) in $(D Configuration).  Disabling
_warning log messages at compile time or at run time also disables lower
severity messages, e.g. info.

Example:
---
log!warning("A warning message!");
---
+/
alias Severity.warning warning;

/++
Info log messages are disabled at compiled time by setting the version to
'strip_log_info'. Info log messages are disabled at run time by setting the
minimum severity to $(D Level.warning) in $(D Configuration).  Disabling _info
log messages at compile time or at run time also disables verbose log messages.

Example:
---
log!info("An info message!");
---
+/
alias Severity.info info;

/++
Verbose log messages are log at the info severity _level. To disable them at
compile time set the version to 'strip_log_info' which also disables all
messages of info severity at compile time. To enable verbose log messages at
run time use the the maximum verbose _level property and the verbose filter
property in $(D Configuration).

Example:
---
vlog(1)("A verbose 1 message");
---
   +/
auto vlog(string file = __FILE__)(int level)
{
   static if(Severity.info > logImpl!(Severity.info).minSeverity)
   {
      return _noopLogFilter;
   }
   else
   {
      return _info.vlog(level, file);
   }
}

/++
Maps to the $(D LogFilter) for the specified severity.

Example:
---
log!info("Info severity message");
log!warning("Warning severity message");
log!error("Error severity message");
log!critical("Critical severity message");
log!fatal("Fatal severity message");
---
+/
template log(Severity severity)
{
   alias logImpl!(severity).filter log;
}

template logImpl(Severity severity)
{
   version(strip_log_error) private alias Severity.critical minSeverity;
   else version(strip_log_warning) private alias Severity.error minSeverity;
   else version(strip_log_info) private alias Severity.warning minSeverity;
   else private alias Severity.info minSeverity;

   static if(severity > minSeverity) alias NoopLogFilter._singleton filter;
   else
   {
      static if(severity == Severity.info) alias _info filter;
      else static if(severity == Severity.warning) alias _warning filter;
      else static if(severity == Severity.error) alias _error filter;
      else static if(severity == Severity.critical) alias _critical filter;
      else static if(severity == Severity.fatal) alias _fatal filter;
   }
}

unittest
{
   auto logger = new shared(TestLogger);
   auto testConfig = new Configuration(logger);
   testConfig.minSeverity = Severity.warning;

   auto logInfo = new LogFilter(Severity.info, testConfig);
   auto logWarning = new LogFilter(Severity.warning, testConfig);
   auto logError = new LogFilter(Severity.error, testConfig);
   auto logCritical = new LogFilter(Severity.critical, testConfig);
   auto logFatal = new LogFilter(Severity.fatal, testConfig);

   auto loggedMessage = "logged message";

   // Test willLog
   assert(!logInfo.willLog);
   assert(logWarning.willLog);
   assert(logError.willLog);
   assert(logCritical.willLog);
   assert(logFatal.willLog);

   // Test logging and severity filtering
   logInfo.write(loggedMessage);
   assert(!logger.called);

   logger.clear();
   logWarning.write(loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.warning &&
          logger.message == loggedMessage);

   logger.clear();
   logError.write(loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.error &&
          logger.message == loggedMessage);

   logger.clear();
   logError.format("%s", loggedMessage);
   assert(logger.called);
   assert(logger.severity == Severity.error &&
          logger.message == loggedMessage);

   logger.clear();
   assertThrown!CriticalException(logCritical.write(loggedMessage));
   assert(logger.called);
   assert(logger.severity == Severity.critical &&
          logger.message == loggedMessage);
   assert(logger.flushCalled);

   logger.clear();
   assertThrown!AssertError(logFatal.write(loggedMessage));
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
log!error("Log an ", to!string(Level.error), " message!");
log!error.write("Log an ", to!string(Level.error), " message!");
log!error.format("Also logs an %s message!", to!string(Level.error));
---
Logs a message if the specified severity level is enabled.

---
void coolFunction(Object object)
{
   log!fatal.when(object is null)("I don't like null objects!");
   // ...
}

foreach(i; 0 .. 10)
{
   log!info.when(first())("Only log this the first time in the loop");
}
---
Logs a message if the specified severity level is enabled and all the user
defined condition are true.
+/
final class LogFilter
{
   this(Severity severity,
        Configuration configuration,
        bool privateBuffer = false)
   {
      enforce(configuration);

      _config = configuration;
      _privateBuffer = privateBuffer;

      _message.severity = severity;
      // XXX remove this when druntime is fixed.
      static if(__traits(hasMember, Thread, "threadId"))
      {
         _message.threadId = Thread.getThis.threadId;
      }
   }

   this() {}

   /++
      Returns true when a message can be logged.

      Example:
      ---
if(log!error.willLog)
{
   string message;
   // Perform some compuration
   // ...
   log!error(message);
}
      ---
    +/
   @property bool willLog()
   {
      return _config !is null && _message.severity <= _config.minSeverity;
   }

   /++
      Returns this object if the parameter $(D now) evaluates to true and if a
      message can be logged. Note: The $(D now) parameter is only evaluated if
      a message can be logged with this object.

      Example:
      ---
foreach(i; 0 .. 10)
{
   log!warning.when(i == 9)("Executed loop when i = 9");
   // ...
}
      ---
    +/
   LogFilter when(lazy bool now)
   {
      if(willLog && now) return this;

      return _noopLogFilter;
   }

   unittest
   {
      auto logger = new shared(TestLogger);
      auto testConfig = new Configuration(logger);

      auto logError = new LogFilter(Severity.error, testConfig);

      auto loggedMessage = "logged message";

      assert(logError.when(rich!"<="(1, 2)).when(rich!"=="(0, 0)).willLog);
   }

   /++
      Returns this object if the parameter $(D now) evaluates to true and if a
      message can be logged. It also appends the log message with a reason why
      it is true. Note: The $(D now) parameter is only evaluated if a message
      can be logged with this object.

      Example:
      ---
foreach(i; 0 .. 10)
{
   log!warning.when(richEqual(i, 9))("Executed loop when i = 9");
   // ...
}
      ---
    +/
   LogFilter when(lazy Rich!bool now)
   {
      if(willLog && now.value)
      {
         auto filter = this;
         if(!_privateBuffer)
         {
            filter = new LogFilter(_message.severity, _config, true);
         }
         else filter.writer.put("&& ");

         filter.writer.put("when(");
         filter.writer.put(now.reason);
         filter.writer.put(") ");

         return filter;
      }

      return _noopLogFilter;
   }

   /++
      Concatenates all the arguements and logs them. Note: The parameters are
      only evaluated if a message can be logged.

      Example:
      ---
auto pi = 3.14159265;

log!info.write("The value of pi is ", pi);

// The same as above...
log!info("The value of pi is ", pi);
      ---
    +/
   void write(string file = __FILE__, int line = __LINE__, T...)(lazy T args)
   {
      // XXX change this to use formattedWrite's new format string
      if(willLog)
      {
         scope(exit) handleSeverity();

         // XXX move this to format when I start using the new formattedWrite
         _message.file = file;
         _message.line = line;

         // record message
         scope(exit) writer.clear();
         writer.reserve(1);
         foreach(T, arg; args) writer.put(to!(char[])(arg));
         _message.message = writer.data;

         // record the time stamp
         _message.time = Clock.currTime(UTC());

         _config.logger.log(_message);
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
         scope(exit) handleSeverity();

         _message.file = file;
         _message.line = line;

         // record message
         scope(exit) writer.clear();
         writer.reserve(fmt.length);
         formattedWrite(writer, fmt, args);
         _message.message = writer.data;

         // record the time stamp
         _message.time = Clock.currTime(UTC());

         _config.logger.log(_message);
      }
   }

   private void handleSeverity()
   {
      if(_message.severity == Severity.fatal)
      {
         /+
          + The other of the scope(exit) is important. We want
          + _fatalHandler to run before the assert.
          +/
         scope(exit) assert(false);
         scope(exit) _config.fatalHandler();
         _config.logger.flush();
      }
      else if(_message.severity == Severity.critical)
      {
         _config.logger.flush();
         throw new CriticalException(_message.message.idup);
      }
   }

   unittest
   {
      auto loggedMessage = "Verbose log message";

      auto logger = new shared(TestLogger);
      auto testConfig = new Configuration(logger);
      testConfig.minSeverity = Severity.warning;
      testConfig.maxVerboseLevel = 3;
      testConfig.verboseFilter = "*log.d=2";

      auto logInfo = new LogFilter(Severity.info, testConfig);
      auto logWarning = new LogFilter(Severity.warning, testConfig);

      // Test vlogging and module filtering
      logger.clear();
      auto verboseLog = logWarning.vlog(2);
      assert(verboseLog.willLog);
      verboseLog.write(loggedMessage);
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
      verboseLog = logWarning.vlog(3);
      verboseLog.write(loggedMessage);
      assert(!logger.called);

      // test wrong module
      logger.clear();
      verboseLog = logWarning.vlog(4, "not_this");
      verboseLog.format("%s", loggedMessage);
      assert(!logger.called);

      // test verbose level
      logger.clear();
      verboseLog = logWarning.vlog(3, "not_this");
      verboseLog.format("%s", loggedMessage);
      assert(logger.called);
      assert(logger.severity == Severity.warning &&
            logger.message == loggedMessage);

      // test severity config too high
      logger.clear();
      auto infoVerboseLog = logInfo.vlog(2);
      assert(!infoVerboseLog.willLog);
      infoVerboseLog.format("%s", loggedMessage);
      assert(!logger.called);
   }

   LogFilter vlog(int level, string file = __FILE__)
   {
      if(willLog && _config.matchesVerboseFilter(file, level))
      {
         return this;
      }

      return _noopLogFilter;
   }

   private @property ref Appender!(char[]) writer()
   {
      if(_privateBuffer) return _privateWriter;
      else return _threadWriter;
   }

   private Logger.LogMessage _message;
   private Configuration _config;
   private bool _privateBuffer;
   private Appender!(char[]) _privateWriter;

   private static Appender!(char[]) _threadWriter;

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
      filter.when(true).write("message");
      filter.when(rich!"=="(0, 0)).write("better message");
      filter.vlog(0, "file");
      filter.vlog(0);
   }

   assert(__traits(compiles, publicInterface!LogFilter));
   assert(__traits(compiles, publicInterface!NoopLogFilter));
}

// Used by the module to disable logging at compile time.
final class NoopLogFilter
{
   pure nothrow const @property bool willLog() { return false; }

   nothrow const ref const(NoopLogFilter) when(lazy bool now)
   { return this; }
   nothrow const ref const(NoopLogFilter) when(lazy Rich!bool now)
   { return this; }

   nothrow const void write(T...)(lazy T args) {}
   alias write opCall;
   nothrow const void format(T...)(lazy string fmt, lazy T args) {}

   pure nothrow const ref const(NoopLogFilter) vlog(int level,
                                                    string file = null)
   { return this; }

   private this() {}

   private static immutable NoopLogFilter _singleton;

   shared static this() { _singleton = new immutable(NoopLogFilter); }
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
   auto testConfig = new Configuration(new shared(TestLogger));
   assert(testConfig.minSeverity == Severity.error);

   auto name = "program_name";
   auto args = [name,
                "--" ~ Configuration.minSeverityFlag,
                "info",
                "--" ~ Configuration.verboseFilterFlag,
                "*logging=2,module=0",
                "--" ~ Configuration.maxVerboseLevelFlag,
                "3",
                "--ignoredOption"];

   testConfig.parseCommandLine(args);

   // assert that all expected options where removed
   assert(args.length == 2);
   assert(args[0] == name);

   assert(testConfig.minSeverity == Severity.info);

   // assert max verbose level
   assert(testConfig.matchesVerboseFilter("file", 3));

   // assert vmodule entries
   assert(testConfig.matchesVerboseFilter("std/logging.d", 2));
   assert(testConfig.matchesVerboseFilter("module.d", 0));

   // === test changing the flag ===
   // remember the defaults
   auto defaultSeverityFlag = Configuration.minSeverityFlag;
   auto defaultFilterFlag = Configuration.verboseFilterFlag;
   auto defaultLevelFlag = Configuration.maxVerboseLevelFlag;

   // change the default
   Configuration.minSeverityFlag = "severity";
   Configuration.verboseFilterFlag = "filter";
   Configuration.maxVerboseLevelFlag = "level";

   args = [name,
           "--" ~ Configuration.minSeverityFlag,
           "warning",
           "--" ~ Configuration.verboseFilterFlag,
           "*log=2,unittest.d=0",
           "--" ~ Configuration.maxVerboseLevelFlag,
           "4",
           "--" ~ defaultSeverityFlag,
           "--" ~ defaultFilterFlag,
           "--" ~ defaultLevelFlag];

   testConfig.parseCommandLine(args);

   // assert that all expected options where removed
   assert(args.length == 4);
   assert(args[0] == name);

   assert(testConfig.minSeverity == Severity.warning);

   // assert max verbose level
   assert(testConfig.matchesVerboseFilter("file", 4));

   // assert vmodule entries
   assert(testConfig.matchesVerboseFilter("std/log.d", 2));
   assert(testConfig.matchesVerboseFilter("unittest.d", 0));

   // reset the defaults
   Configuration.minSeverityFlag = defaultSeverityFlag;
   Configuration.verboseFilterFlag = defaultFilterFlag;
   Configuration.maxVerboseLevelFlag = defaultLevelFlag;

   // === test that an error in parseCommandLine doesn't invalidate object
   args = [name,
           "--" ~ Configuration.minSeverityFlag,
           "info",
           "--" ~ Configuration.verboseFilterFlag,
           "*logging=2,module=abc",
           "--" ~ Configuration.maxVerboseLevelFlag,
           "3",
           "--ignoredOption"];

   // set known values
   testConfig.minSeverity = Severity.error;
   testConfig.verboseFilter = "log=2";
   testConfig.maxVerboseLevel = 1;

   assertThrown(testConfig.parseCommandLine(args));

   // test that nothing changed
   assert(testConfig.minSeverity == Severity.error);
   assert(testConfig.verboseFilter == "log=2");
   assert(testConfig.maxVerboseLevel = 1);
}

/++
Module configuration.

This object is used to configure the logging module if the default behavior is
not wanted.
+/
final class Configuration
{
   /++
      Initialize the configuration object based on the passed parameter.

      The function processes every entry in commandLine looking for valid
      command line options. All of the valid options are enumerated in the
      static fields of this structure that end in 'Flag', e.g. minSeverityFlag.
      When a valid command line option is found its value is stored in the
      mapping object's property and it is removed from commandLine. For any
      property not set explictly its default value is used. Here is a list of
      all the flags and how they map to the object's property:

      $(UL
         $(LI $(D minSeverityFlag) maps to $(D minSeverity))
         $(LI $(D verboseFilterFlag) maps to $(D verboseFilter))
         $(LI $(D maxVerboseLevelFlag) maps to $(D maxVerboseLevel)))

      Any valid field is removed from commandLine; any invalid field is left in
      commandLine.

      Note:
      A call to the function is not required if the module will be initialized
      using the command line's default options.
    +/
   void parseCommandLine(ref string[] commandLine)
   {
      auto severity = minSeverity;
      auto level = maxVerboseLevel;
      auto filter = verboseFilter;

      getopt(commandLine,
             std.getopt.config.passThrough,
             minSeverityFlag, &severity,
             verboseFilterFlag, &filter,
             maxVerboseLevelFlag, &level);

      // try verbose filter first
      verboseFilter = filter;
      minSeverity = severity;
      maxVerboseLevel = level;
   }

   /++
      Command line flag for setting the minimum severity level. The default
      value is "minloglevel" which at the command line is '--minloglevel'.
    +/
   static shared string minSeverityFlag = "minloglevel";

   /++
      Command line flag for setting the verbose configuration per module.  The
      default value is "vmodule" which at the command line is '--vmodule'.
    +/
   static shared string verboseFilterFlag = "vmodule";

   /++
      Command line flag for setting the maximum verbose level. The default
      value is "v" which at the command line is '--v'.
    +/
   static shared string maxVerboseLevelFlag = "v";

   unittest
   {
      auto testConfig = new Configuration(new shared(TestLogger));

      assert((testConfig.minSeverity = Severity.fatal) == Severity.critical);
      assert((testConfig.minSeverity = Severity.critical) == Severity.critical);
      assert((testConfig.minSeverity = Severity.error) == Severity.error);
   }

   /++
      Specifies the minimum _severity of the messages that are logged.

      Only messages with a _severity greater than or equal to the value of this
      property are logged.

      The default value is $(D Severity.error).
    +/
   @property Severity minSeverity(Severity severity)
   {
      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;

      // cannot disable critical severity
      _minSeverity = severity < Severity.critical ?
                                Severity.critical :
                                severity;
      return _minSeverity;
   }
   /// ditto
   @property Severity minSeverity()
   {
      synchronized(_rwmutex.reader) return _minSeverity;
   }

   unittest
   {
      auto testConfig = new Configuration(new shared(TestLogger));

      // Test max verbose level
      testConfig.maxVerboseLevel = 1;
      assert(testConfig.matchesVerboseFilter("file", 1));
      assert(testConfig.matchesVerboseFilter("file", 0));
      assert(!testConfig.matchesVerboseFilter("file", 2));

      assert(testConfig.maxVerboseLevel == 1);
   }

   /++
      Specifies the maximum verbose _level of verbose messages that can logged.

      Verbose messages with a verbose _level less than or equal to the value of
      this property are logged. This property is ignore of the module logging
      the verbose message matches a module specified in the verbose
      configuration for modules property.

      The default value is $(D int.min).
    +/
   @property int maxVerboseLevel(int level)
   {
      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;
      _level = level;

      return _level;
   }
   /// ditto
   @property int maxVerboseLevel()
   {
      synchronized(_rwmutex.reader) return _level;
   }

   unittest
   {
      auto vmodule = "module=1,*another=3,even*=2,cat?=4,*dog?=1,evenmore=10";
      auto testConfig = new Configuration(new shared(TestLogger));
      testConfig.verboseFilter = vmodule;

      // Test exact patterns
      assert(testConfig.matchesVerboseFilter("module", 1));
      assert(testConfig.matchesVerboseFilter("module.d", 1));
      assert(!testConfig.matchesVerboseFilter("amodule", 1));

      // Test *
      assert(testConfig.matchesVerboseFilter("package/another", 3));
      assert(testConfig.matchesVerboseFilter("package/another.d", 3));
      assert(!testConfig.matchesVerboseFilter("package/dontknow", 3));

      assert(testConfig.matchesVerboseFilter("evenmore", 2));
      assert(testConfig.matchesVerboseFilter("evenmore.d", 2));
      assert(!testConfig.matchesVerboseFilter("package/evenmore.d", 2));

      // Test ?
      assert(testConfig.matchesVerboseFilter("cats.d", 4));
      assert(!testConfig.matchesVerboseFilter("cat", 4));

      // Test * and ?
      assert(testConfig.matchesVerboseFilter("package/dogs.d", 1));
      assert(!testConfig.matchesVerboseFilter("package/doggies.d", 1));
      assert(!testConfig.matchesVerboseFilter("package/horse", 1));

      // Test that it can match any of the entries
      assert(testConfig.matchesVerboseFilter("evenmore.d", 10));

      // Test invalid strings
      assertThrown(testConfig.verboseFilter = "module=2,");
      assertThrown(testConfig.verboseFilter = "module=a");
      assertThrown(testConfig.verboseFilter = "module=2,another=");

      // assert output
      assert(vmodule == testConfig.verboseFilter);
   }

   /++
      Specifies the verbose configuration for modules.

      A verbose message with level $(D x) is get logged at severity level info
      if there is an entry that matches to the source file and the verbose
      level of that entry is greater than or equal to $(D x).

      The format of the configuration string is as follow
      "[pattern]=[level],...", where '[pattern]' may contain any character
      allowed in a file name and '[level]' is convertible to an integer.
      Every '*' in '[pattern]' matches any number of characters. Every '?' in
      '[pattern]' matches exactly one character.

      For every '[pattern]=[level]' in the configuration string an entry is
      created.

      Example:
      ---
config.verboseFilter = "module=2,great*=3,*test=1";
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

      The verbose message is not logged even though it is less than or equal to
      2, as specified in the command line.

      The default value is $(D null).
    +/
   @property string verboseFilter(string vmodule)
   {
      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;

      typeof(_modulePatterns) patterns;
      typeof(_moduleLevels) levels;

      foreach(entry; splitter(vmodule, ","))
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
         levels ~= to!int(entryParts[1]);
      }
      assert(patterns.length == levels.length);

      _modulePatterns = patterns;
      _moduleLevels = levels;
      _vmodule = vmodule;

      return _vmodule;
   }
   /// ditto
   @property string verboseFilter()
   {
      synchronized(_rwmutex.reader) return _vmodule;
   }

   /++
      Function pointer for handling log message with a severity of fatal.

      This function is called by the thread trying to log a fatal message. The
      function handler should not return; otherwise the framework calls
      $(D assert(false)).

      The default value is $(D function void() {}).
    +/
   @property void function() fatalHandler(void function() handler)
   {
      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;

      _fatalHandler = handler ? handler : function void() {};

      return _fatalHandler;
   }

   /++
      Implementation of the $(D Logger) interface used to persiste log messages

      This property allows the caller to change and configure the the backend
      logger to a different $(D Logger). It will throw an exception if it is
      changed after a logging call has been made.

      The default value a $(D FileLogger).

      Example:
      ---
import std.log;

class NullLogger : Logger
{
   shared void log(const ref LogMessage message) {}
   shared void flush() {}
}

void main(string[] args)
{
   config.logger = new NullLogger();
   // ...
}
      ---
      This example disables writing log messages at run time.
    +/
   @property shared(Logger) logger(shared(Logger) logger)
   {
      enforce(logger);

      enforce(_rwmutex.writer.tryLock);
      scope(exit) _rwmutex.writer.unlock;

      // it is a error if the user tries to init after the logger has been used
      enforce(!_loggerUsed);
      _logger = logger;

      return _logger;
   }
   /// ditto
   @property shared(Logger) logger()
   {
      synchronized(_rwmutex.reader)
      {
         // Somebody asked for the logger don't allow changing it
         _loggerUsed = true;
         return _logger;
      }
   }

   private this(shared(Logger) logger)
   {
      enforce(logger);

      _rwmutex = new ReadWriteMutex(ReadWriteMutex.Policy.PREFER_READERS);
      _logger = logger;
      _fatalHandler = function void() {};
   }

   private @property void function() fatalHandler()
   {
      synchronized(_rwmutex.reader) return _fatalHandler;
   }

   private bool matchesVerboseFilter(string file, int level)
   {
      synchronized(_rwmutex.reader)
      {
         assert(_modulePatterns.length == _moduleLevels.length);

         bool matchedFile;
         foreach(i; 0 .. _modulePatterns.length)
         {
            foreach(pattern; _modulePatterns[i])
            {
               if(pattern !is null && fnmatch(file, pattern))
               {
                  if(level <= _moduleLevels[i]) return true;

                  matchedFile = true;
                  break;
               }
            }
         }

         return !matchedFile && level <= _level;
      }
   }

   private Severity _minSeverity = Severity.error;
   private void function() _fatalHandler;

   // verbose filtering variables
   private int _level = int.min;
   private string[2][] _modulePatterns;
   private int[] _moduleLevels;
   private string _vmodule;

   // backend logger variables
   private bool _loggerUsed;
   private shared Logger _logger;

   private ReadWriteMutex _rwmutex;
}

unittest
{
   ushort passed;
   auto message = Logger.LogMessage.init;
   message.time = Clock.currTime;

   auto loggerConfig = FileLogger.Configuration.create();
   loggerConfig.name = "test";


   // test info message
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.info;
   auto logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(canFind(key, ".INFO.log.") && data.lines.length == 2) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 1);

   // test warning message
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.warning;
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(canFind(key, ".INFO.log.") && data.lines.length == 2 ||
         canFind(key, ".WARNING.log.") && data.lines.length == 2) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 2);

   // test log to stderr
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.error;

   loggerConfig.logToStderr = true;
   loggerConfig.stderrThreshold = Severity.error;
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(key == "stderr file" && data.lines.length == 1) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 1);

   // test also log to stderr
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.error;

   loggerConfig.logToStderr = false;
   loggerConfig.alsoLogToStderr = true;
   loggerConfig.stderrThreshold = Severity.error;
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(canFind(key, ".INFO.log.") && data.lines.length == 2 ||
         canFind(key, ".WARNING.log.") && data.lines.length == 2 ||
         canFind(key, ".ERROR.log.") && data.lines.length == 2 ||
         key == "stderr file" && data.lines.length == 1) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 4);

   // test log dir
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.info;

   loggerConfig.alsoLogToStderr = false;
   loggerConfig.logDirectory = "/dir";
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(startsWith(key, "/dir/") && data.lines.length == 2) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 1);

   // test buffer size
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.info;

   loggerConfig.logDirectory = "";
   loggerConfig.bufferSize = 32;
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(canFind(key, ".INFO.log.") && data.bufferSize == 32) ++passed;
      else assert(data.bufferSize == 0);
   }
   assert(passed == 1);

   // test severity symbols
   TestWriter.clear();
   passed = 0;
   loggerConfig = FileLogger.Configuration.create();
   loggerConfig.severitySymbols = "12345";
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(canFind(key, ".INFO.log.") && data.lines.length == 2)
      {
         assert(startsWith(data.lines[1], "5"));
         ++passed;
      } else assert(data.lines.length == 0);
   }
   assert(passed == 1);

   // test file names - warning message but should only log to info file
   TestWriter.clear();
   passed = 0;
   message.severity = Severity.warning;
   loggerConfig = FileLogger.Configuration.create();
   loggerConfig.logFileNamePrefixes(["F", "C", "E", "", "I"]);
   logger = new shared(FileLogger)(loggerConfig);
   logger.log(message);
   foreach(key, ref data; TestWriter.writers)
   {
      if(startsWith(key, "I.log.") && data.lines.length == 2) ++passed;
      else assert(data.lines.length == 0);
   }
   assert(passed == 1);
}

/++
Default $(D Logger) implementation.

This logger implements all the configuration option described in
$(D FileLogger.Configuration). This logger writes log messages to multiple
files. There is a file for every severity level. Log messages of a given
severity are written to all the log files of an equal or lower severity. E.g.
A log message of severity warning will be written to the log files for warning
and info but not to the log files of fatal and error.
+/
class FileLogger : Logger
{
   unittest
   {
      auto name = "program_name";
      // assert default values
      auto loggerConfig = Configuration.create();
      loggerConfig.name = name;
      assert(loggerConfig.name == name);
      assert(loggerConfig.logToStderr == false);
      assert(loggerConfig.alsoLogToStderr == false);
      assert(loggerConfig.stderrThreshold == Severity.error);
      // can't test logDirectory as it is env dependent

      auto args = [name,
                   "--" ~ Configuration.logToStderrFlag,
                   "--" ~ Configuration.stderrThresholdFlag, "fatal",
                   "--" ~ Configuration.logDirectoryFlag, "/tmp",
                   "--ignoredOption"];

      loggerConfig.parseCommandLine(args);
      assert(args.length == 2);
      assert(args[0] == name);

      assert(loggerConfig.name == name);
      assert(loggerConfig.logToStderr);
      assert(!loggerConfig.alsoLogToStderr);
      assert(loggerConfig.stderrThreshold == Severity.fatal);
      assert(loggerConfig.logDirectory == "/tmp");

      // test alsoLogToStderr
      args = [name, "--" ~ Configuration.alsoLogToStderrFlag];

      loggerConfig = Configuration.create();
      loggerConfig.parseCommandLine(args);
      assert(loggerConfig.alsoLogToStderr);
   }

   /++
      Structure for configuring the default backend logger.
    +/
   public struct Configuration
   {
      /++
         Create a configuration object based on the passed parameter.

         The function processes every entry in commandLine looking for valid
         command line options. All of the valid options are enumerated in the
         static fields of this structure that end in 'Flag', e.g.
         logToStderrFlag. When a valid command line option is found its value
         is stored in the mapping object's property. For any property not set
         explictly its default value is used. Here is a list of all the flags
         and how they map to the object's property:

         $(UL
            $(LI $(D logToStderrFlag) maps to $(D logToStderr))
            $(LI $(D alsoLogToStderrFlag) maps to $(D alsoLogToStderr))
            $(LI $(D stderrThresholdFlag) maps to $(D stderrThreshold))
            $(LI $(D logDirectoryFlag) maps to $(D logDirectory)))

         Any valid field is removed from commandLine; any invalid field is
         left in commandLine.

         The $(D name) property is set to the program name, i.e. the first
         element of commandLine.
       +/
      void parseCommandLine(ref string[] commandLine)
      {
         enforce(commandLine.length > 0);

         bool logToStderr = _logToStderr;
         bool alsoLogToStderr = _alsoLogToStderr;
         Severity stderrThreshold = _stderrThreshold;
         string logDirectory = _logDirectory;

         getopt(commandLine,
                std.getopt.config.passThrough,
                logToStderrFlag, &logToStderr,
                alsoLogToStderrFlag, &alsoLogToStderr,
                stderrThresholdFlag, &stderrThreshold,
                logDirectoryFlag, &logDirectory);

         _name = commandLine[0];
         _logToStderr = logToStderr;
         _alsoLogToStderr = alsoLogToStderr;
         _stderrThreshold = stderrThreshold;
         _logDirectory = logDirectory;
      }

      /++
         Command line flag for logging to stderr. The default value is
         "logtostderr" which at the command line is '--logtostderr'.
       +/
      static string logToStderrFlag = "logtostderr";

      /++
         Command line flag for logging to stderr and files. The default value
         is "alsologtostderr" which at the command line is '--alsologtostderr'.
       +/
      static string alsoLogToStderrFlag = "alsologtostderr";

      /++
         Command line flag for setting the stderr logging threshold. The
         default value is "stderrthreshold" which at the command line is
         '--stderrthreshold'.
       +/
      static string stderrThresholdFlag = "stderrthreshold";

      /++
         Command line flag for setting the logging directory. The default
         value is "logdir" which at the command line is '--logdir'.
       +/
      static string logDirectoryFlag = "logdir";

      /// Create file logger configuration.
      static Configuration create()
      {
         Configuration loggerConfig;

         loggerConfig._name = Runtime.args[0];

         // get default log dir
         loggerConfig._logDirectory = getenv("LOGDIR");
         if(loggerConfig._logDirectory is null)
         {
            loggerConfig._logDirectory = getenv("TEST_TMPDIR");
         }

         return loggerConfig;
      }

      /++
         Name to use when generating log file names.

         The default value is the program name.
       +/
      @property string name(string name) { return _name = name; }
      @property const string name() { return _name; }

      /++
         Specifies if the logger should write to stderr. If this property is
         set, then it only logs to stderr and not to files.

         The default value is false.
       +/
      @property bool logToStderr(bool logToStderr)
      {
         return _logToStderr = logToStderr;
      }
      @property const bool logToStderr() { return _logToStderr; } /// ditto

      /++
         Specifies if the logger should write to stderr. If this property is
         set, then it logs to stderr and to files.

         The default value is false.
       +/
      @property bool alsoLogToStderr(bool alsoLogToStderr)
      {
         return _alsoLogToStderr = alsoLogToStderr;
      }
      /// ditto
      @property const bool alsoLogToStderr() { return _alsoLogToStderr; }

      /++
         Specifies the _threshold at which log messages are logged to stderr.
         Any message of higher or equal severity to threshold is written to
         stderr.

         The default value is $(D Severity.error).
       +/
      @property Severity stderrThreshold(Severity threshold)
      {
         return _stderrThreshold = threshold;
      }
      /// ditto
      @property const Severity stderrThreshold() { return _stderrThreshold; }

      /++
         Specifies the directory where log files are created.

         The default value for this property is the value in the enviroment
         variable 'LOGDIR'. If 'LOGDIR' is not set, then 'TEST_TMPDIR' is
         used. If 'TEST_TMPDIR' is not set, then it logs to the current
         directory.
       +/
      @property string logDirectory(string logDirectory)
      {
         return _logDirectory = logDirectory;
      }
      @property const string logDirectory() { return _logDirectory; } /// ditto

      /++
         Specifies the buffer size for each log file.

         The default value is 4KB.
       +/
      @property size_t bufferSize(size_t bufferSize)
      {
         return _bufferSize = bufferSize;
      }
      @property const size_t bufferSize() { return _bufferSize; } /// ditto

      unittest
      {
         auto testConfig = Configuration.create();
         assert((testConfig.logLineFormat = "%%") == "%%");
         assert((testConfig.logLineFormat = "%t") == "%t");
         assert((testConfig.logLineFormat = "%i") == "%i");
         assert((testConfig.logLineFormat = "%f") == "%f");
         assert((testConfig.logLineFormat = "%l") == "%l");
         assert((testConfig.logLineFormat = "%s") == "%s");
         assert((testConfig.logLineFormat = "%m") == "%m");
         assert((testConfig.logLineFormat = "%t%i%f%l%s%m") == "%t%i%f%l%s%m");

         assertThrown(testConfig.logLineFormat = "% ");
         assertThrown(testConfig.logLineFormat = "%k");

         assert((testConfig.logLineFormat = "string without percent") ==
                "string without percent");
         assert((testConfig.logLineFormat = "%sseverity%mmessage") ==
                "%sseverity%mmessage");

         // date formatting tests
         assert((testConfig.logLineFormat = "%{%d}t") == "%{%d}t");
         assert((testConfig.logLineFormat = "%{%Y}t") == "%{%Y}t");
         assert((testConfig.logLineFormat = "%{%H}t") == "%{%H}t");
         assert((testConfig.logLineFormat = "%{%M}t") == "%{%M}t");
         assert((testConfig.logLineFormat = "%{%S}t") == "%{%S}t");
         assert((testConfig.logLineFormat = "%{%m}t") == "%{%m}t");
         assert((testConfig.logLineFormat = "%{%d %Y %H %M %S %m}t") ==
                "%{%d %Y %H %M %S %m}t");
         assert((testConfig.logLineFormat =
                  "%{%d}t %{%Y}t %{%H}t %{%M}t %{%S}t %{%m}t") ==
                "%{%d}t %{%Y}t %{%H}t %{%M}t %{%S}t %{%m}t");

         // the result should be accepted by formattedWrite
         auto bh = appender!string();
         testConfig.logLineFormat = "%%%t%i%f%l%s%m%{%d %Y %H %M %S %m}t";
         formattedWrite(bh, testConfig._internalLogLineFormat,
                        1, "", 1, "", "", 1, 1, 1, 1, 1, 1);
      }

      /++
         Specifies the format for every log line.

         The string can contain literal characters copied into the log files
         and the C-style control characters "\n" and "\t" to represent
         new-lines and tabs. Literal quotes and backslashes should be escaped
         with backslashes.

         The attributes of a log line are logged by placing "%" directives in
         the format string.

         $(BOOKTABLE Directives are mapped to logging values as follow.,
            $(TR $(TH Directive)
                 $(TH Semantics))
            $(TR $(TD %%)
                 $(TD The percent sign.))
            $(TR $(TD %{...}t)
                 $(TD The time when the log line was generated.))
            $(TR $(TD %H)
                 $(TD The hour as a decimal number using a 24-hour clock.))
            $(TR $(TD %i)
                 $(TD The id of the thread which generated the log line.))
            $(TR $(TD %M)
                 $(TD The minute as a decimal number.))
            $(TR $(TD %f)
                 $(TD The name of the file which generated the log line.))
            $(TR $(TD %S)
                 $(TD The second as a decimal number.))
            $(TR $(TD %m)
                 $(TD The log message.)))

         For $(B %{...}t) the $(B {...}) is optional.

         $(BOOKTABLE  Directives inside the curly brakets in $(B %{...}t) are
                      mapped as follows.,
            $(TR $(TH Directive)
                 $(TH Semantics))
            $(TR $(TD %%)
                 $(TD The percent sign.))
            $(TR $(TD %m)
                 $(TD The month as a decimal number.))
            $(TR $(TD %d)
                 $(TD The day of the month as a decimal number.))
            $(TR $(TD %Y)
                 $(TD The year as a decimal number including the century.))
            $(TR $(TD %H)
                 $(TD The hour as a decimal number using a 24-hour clock.))
            $(TR $(TD %M)
                 $(TD The minute as a decimal number.))
            $(TR $(TD %S)
                 $(TD The second as a decimal number.)))

         The default value is $(D "%s%t %i %f:%l] %m").
       +/
      @property string logLineFormat(string format)
      {
         static const string threadIdFormat = "%1$x";
         static const string fileFormat = "%2$s";
         static const string lineFormat = "%3$d";
         static const string severityFormat = "%4$s";
         static const string messageFormat = "%5$s";
         static const string yearFormat = "%6$.2d";
         static const string monthFormat = "%7$.2d";
         static const string dayFormat = "%8$.2d";
         static const string hourFormat = "%9$.2d";
         static const string minuteFormat = "%10$.2d";
         static const string secondFormat = "%11$.2d";

         auto result = appender!string();
         enum State { start, escaped,
                      dateFormat, dateFormatEscaped, dateFormatFinished };
         State state;
         foreach(size_t i, f; format)
         {
            final switch(state)
            {
               case State.escaped:
                  switch(f)
                  {
                     case '{':
                        state = State.dateFormat;
                        break;
                     case '%':
                        result.put("%%");
                        state = State.start;
                        break;
                     case 't':
                        result.put(monthFormat ~ dayFormat ~ " " ~
                                   hourFormat ~ ":" ~ minuteFormat ~ ":" ~
                                   secondFormat);
                        state = State.start;
                        break;
                     case 'i':
                        result.put(threadIdFormat);
                        state = State.start;
                        break;
                     case 'f':
                        result.put(fileFormat);
                        state = State.start;
                        break;
                     case 'l':
                        result.put(lineFormat);
                        state = State.start;
                        break;
                     case 's':
                        result.put(severityFormat);
                        state = State.start;
                        break;
                     case 'm':
                        result.put(messageFormat);
                        state = State.start;
                        break;
                     default:
                        throw new Exception("Error parsing '" ~
                                            format ~
                                            "' at postion " ~
                                            to!string(i) ~
                                            " found invalid character '" ~
                                            to!string(f) ~
                                            "'.");
                  }
                  break;
               case State.dateFormat:
                  switch(f)
                  {
                     case '%':
                        state = State.dateFormatEscaped;
                        break;
                     case '}':
                        state = State.dateFormatFinished;
                        break;
                     default:
                        result.put(f);
                  }
                  break;
               case State.dateFormatEscaped:
                  switch(f)
                  {
                     case '%':
                        result.put("%%");
                        state = State.dateFormat;
                        break;
                     case 'd':
                        result.put(dayFormat);
                        state = State.dateFormat;
                        break;
                     case 'Y':
                        result.put(yearFormat);
                        state = State.dateFormat;
                        break;
                     case 'H':
                        result.put(hourFormat);
                        state = State.dateFormat;
                        break;
                     case 'M':
                        result.put(minuteFormat);
                        state = State.dateFormat;
                        break;
                     case 'S':
                        result.put(secondFormat);
                        state = State.dateFormat;
                        break;
                     case 'm':
                        result.put(monthFormat);
                        state = State.dateFormat;
                        break;
                     default:
                        throw new Exception("Error parsing '" ~
                                            format ~
                                            "' at postion " ~
                                            to!string(i) ~
                                            " found invalid character '" ~
                                            to!string(f) ~
                                            "'.");
                  }
                  break;
               case State.dateFormatFinished:
                  switch(f)
                  {
                     case 't':
                        state = State.start;
                        break;
                     default:
                        throw new Exception("Error parsing '" ~
                                            format ~
                                            "' at postion " ~
                                            to!string(i) ~
                                            " found invalid character '" ~
                                            to!string(f) ~
                                            "'.");
                  }
                  break;
               case State.start:
                  switch(f)
                  {
                     case '%':
                        state = State.escaped;
                        break;
                     default:
                        result.put(f);
                  }
                  break;
            }
         }

         result.put(newline[]);

         _internalLogLineFormat = result.data;
         return _logLineFormat = format;
      }
      @property string logLineFormat() { return _logLineFormat; } /// ditto

      unittest
      {
         auto loggerConfig = FileLogger.Configuration.create();

         assert((loggerConfig.severitySymbols = "12345") == "12345");
         assertThrown(loggerConfig.severitySymbols = "1234");
         assertThrown(loggerConfig.severitySymbols = "123456");
      }

      /++
         Specifies the symbols to use in the log line for severities.

         The value of the severity as define in Severity is used to index into
         the string. The length of the string must equal $(D Severity.max + 1).

         Example:
         ---
auto loggerConfig = FileLogger.Configuration.create();
assert(loggerConfig.severitySymbols[Severity.fatal] == 'F');
         ---

         The default value is $(D "FCEWI").
         +/
      @property dstring severitySymbols(dstring symbols)
      {
         enforce(symbols.length == Severity.max + 1);

         return _severitySymbols = symbols;
      }
      /// ditto
      @property dstring severitySymbols() { return _severitySymbols; }

      unittest
      {
         auto testConfig = FileLogger.Configuration.create();

         assert(testConfig.logFileNamePrefixes(["F", "C", "E", "", "I"]) ==
                ["F", "C", "E", "", "I"]);
         assert(testConfig.logFileNamePrefixes(null) == null);
         assertThrown(testConfig.logFileNamePrefixes(["F"]));
         assertThrown(testConfig.logFileNamePrefixes(["", "", "", "", "", ""]));
      }

      /++
         Specifies the prefix for the name of log files.

         If this value is specified the log file of severity error will have
         the prefix $(D logFileNamePrefixes[Severity.error]). prefixes should
         either by null or the length must equal $(Severity.max + 1). If the
         value is null then log file names are
         "<program>.<hostname>.<user>.<severity>.log.<datetime>.<pid>" (E.g.
         hello.example.com.guest.log.INFO.20110609T050018Z.743).

         If an entry contains the empty string a log file will not be created
         for that severity.

         The default value is $(D null).
       +/
      @property string[] logFileNamePrefixes(string[] prefixes)
      {
         enforce(prefixes == null || prefixes.length == Severity.max + 1);

         return _logFileNamePrefixes = prefixes;
      }
      /// ditto
      @property string[] logFileNamePrefixes() { return _logFileNamePrefixes; }

      /++
         Specifies the extension for the name of log files.

         The default value is $(D ".log").
       +/
      @property string logFileNameExtension(string extension)
      {
         return _logFileNameExtension = extension;
      }
      /// ditto
      @property string logFileNameExtension() { return _logFileNameExtension; }

      private @property string internalLogLineFormat()
      {
         if(_internalLogLineFormat is null) logLineFormat = _logLineFormat;

         return _internalLogLineFormat;
      }

      private string _name;
      private bool _logToStderr;
      private bool _alsoLogToStderr;
      private Severity _stderrThreshold = Severity.error;
      private string _logDirectory;
      private size_t _bufferSize = 4 * 1024;
      private string _logLineFormat = "%s%t %i %f:%l] %m";
      private string _internalLogLineFormat;
      private dstring _severitySymbols = "FCEWI";
      private string[] _logFileNamePrefixes;
      private string _logFileNameExtension = ".log";
   }

   /++
      Constructs a logger with the configuration specified in loggerConfig.
    +/
   this(Configuration loggerConfig)
   {
      enforce(loggerConfig.name);

      _bufferSize = loggerConfig.bufferSize;
      _logLineFormat = loggerConfig.logLineFormat;
      _internalLogLineFormat = loggerConfig.internalLogLineFormat;
      _severitySymbols = loggerConfig.severitySymbols;
      _mutex = new Mutex;

      // init hostname
      _hostname = hostname;

      // Create file for every severity; add one more for stderr
      _writers = new Writer[Severity.max + 2];
      _writers[$ - 1] = stderr; // add stderr

      // create the indices for all the loggers
      _indices = new size_t[][Severity.max + 1];
      foreach(i, ref index; _indices)
      {
         if(loggerConfig.logToStderr)
         {
            // Only log to stderr
            if(i <= loggerConfig.stderrThreshold) index ~= _writers.length - 1;
         }
         else
         {
            // Add the file writers
            foreach(j; i .. _writers.length - 1) index ~= j;

            // Add stderr if needed
            if(loggerConfig.alsoLogToStderr &&
               i <= loggerConfig.stderrThreshold)
            {
               index ~= _writers.length - 1;
            }
         }
      }

      auto time = Clock.currTime(UTC());
      // we dont need fracsec for the file name.
      time.fracSec = FracSec.from!"msecs"(0);

      // create the file name for all the writers
      auto nameBuffer = appender!(char[])();
      if(loggerConfig.logFileNamePrefixes)
      {
         foreach(prefix; loggerConfig.logFileNamePrefixes)
         {
            if(prefix != null)
            {
               nameBuffer.clear();
               formattedWrite(nameBuffer,
                              "%s%s.%s.%s",
                              prefix,
                              loggerConfig.logFileNameExtension,
                              time.toISOString(),
                              getpid());
               _filenames ~= std.path.join(loggerConfig.logDirectory,
                                           nameBuffer.data);

               nameBuffer.clear();
               formattedWrite(nameBuffer,
                              "%s%s",
                              prefix,
                              loggerConfig.logFileNameExtension);
               _symlinks ~= std.path.join(loggerConfig.logDirectory,
                                          nameBuffer.data);
            }
            else
            {
               _filenames ~= null;
               _symlinks ~= null;
            }
         }
      }
      else
      {
         foreach(severity; 0 .. _writers.length - 1)
         {
            nameBuffer.clear();
            formattedWrite(nameBuffer,
                           "%s.%s.%s.%s%s.%s.%s",
                           loggerConfig.name,
                           _hostname,
                           username,
                           toupper(to!string(cast(Severity)severity)),
                           loggerConfig.logFileNameExtension,
                           time.toISOString(),
                           getpid());
            _filenames ~= std.path.join(loggerConfig.logDirectory,
                                        nameBuffer.data);

            nameBuffer.clear();
            formattedWrite(nameBuffer,
                           "%s.%s%s",
                           loggerConfig.name,
                           toupper(to!string(cast(Severity)severity)),
                           loggerConfig.logFileNameExtension);
            _symlinks ~= std.path.join(loggerConfig.logDirectory,
                                       nameBuffer.data);
         }
      }
   }

   /// Writes a _log message to all the _log files of equal or lower severity.
   shared void log(const ref LogMessage message)
   {
      auto time = cast(DateTime) message.time;
      synchronized(_mutex)
      {
         foreach(i; _indices[message.severity])
         {
            // don't write if we are suppose to have a name but don't have one.
            if(i < _filenames.length && _filenames[i] == null) continue;

            // open file if is not opened and we have a name for it
            if(i < _filenames.length && !_writers[i].isOpen)
            {
               _writers[i].open(_filenames[i], "w");
               _writers[i].setvbuf(_bufferSize);

               _writers[i].writef("Log file created at: %s" ~ newline ~
                                  "Running on machine: %s" ~ newline ~
                                  "Log line format: %s" ~ newline,
                                  time.toISOExtString(),
                                  _hostname,
                                  _logLineFormat);

               // create symlink
               symlink(basename(_filenames[i]), _symlinks[i]);
            }
            _writers[i].writef(_internalLogLineFormat,
                               message.threadId,
                               message.file,
                               message.line,
                               _severitySymbols[message.severity],
                               message.message,
                               time.year,
                               cast(int)time.month,
                               time.day,
                               time.hour,
                               time.minute,
                               time.second);
         }
      }
   }

   /// Flushes the buffer of all the log files.
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

   private @property string hostname()
   {
      // TODO: test in windows
      string name;
      version(Posix)
      {
         utsname buf;
         if(uname(&buf) == 0)
         {
            name = to!string(buf.nodename.ptr);
         }
      }
      else version(Windows)
      {
         char[MAX_COMPUTERNAME_LENGTH + 1] buf;
         if(GetComputerNameA(buf.ptr, buf.length) == 0)
         {
            name = to!string(buf.ptr);
         }
      }

      return name ? name : "unknown";
   }

   private @property string username()
   {
      // TODO: test in windows
      string name;
      version(Posix) name = getenv("LOGNAME");
      else version(Windows) name = getenv("USERNAME");

      return name ? name : "unknown";
   }

   private shared void symlink(string target, string linkName)
   {
      version(unittest) {} // don't have any side effect in unittest
      else version(Posix)
      {
         if(exists(linkName) && isSymLink(linkName)) remove(linkName);
         .symlink(toStringz(target), toStringz(linkName));
      }
      // TODO: Need Windows Vista to test this implementation
   }

   private size_t _bufferSize;
   private string _logLineFormat;
   private string _internalLogLineFormat;
   private dstring _severitySymbols;
   private string _hostname;

   private Mutex _mutex; // rwmutex wont preserve the order
   private string[] _filenames;
   private string[] _symlinks;
   private size_t[][] _indices;
   __gshared Writer[] _writers;

   version(unittest) private alias TestWriter Writer;
   else private alias File Writer;
}

unittest
{
   assert(isWriter!TestWriter);
   assert(isWriter!File);
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
   assert(rich!"=="(1, 1));
   assert(rich!"!="(1, 2));
   assert(rich!">"(2, 1));
   assert(rich!">="(2, 2) && rich!">="(2, 1));
   assert(rich!"<"(1, 2));
   assert(rich!"<="(1, 2) && rich!"<="(1, 1));
   assert(rich!"&&"(rich!"=="(1, 1), rich!"!="(1, 2)));
   assert(rich!"||"(rich!"<"(1, 1), rich!"=="(1, 1)));

   assert(!rich!"=="(1, 2));
   assert(!rich!"!="(1, 1));
   assert(!rich!">"(1, 1));
   assert(!rich!">="(1, 2));
   assert(!rich!"<"(2, 2));
   assert(!rich!"<="(3, 2));
   assert(!rich!"&&"(rich!"=="(1, 1), rich!"!="(1, 1)));
   assert(!rich!"||"(rich!"<="(1, 0), rich!"=="(1, 0)));

   assert(is(typeof(rich!"&&"(rich!"=="(1, 1), rich!"!="(1, 1))) == Rich!bool));
   assert(is(typeof(rich!"=="(1, 2)) == Rich!bool));
}

/++
   Rich data
 +/
template rich(string exp)
   if(isBinaryOp(exp))
{
   Rich!(binaryFunImpl!("a" ~ exp ~ "b", "a", "b").Body!(T, R).ReturnType)
      rich(T, R)(T a, R b)
      if(__traits(compiles, { T a; to!string(a); }) &&
         __traits(compiles, { R b; to!string(b); }))
   {
      auto value = binaryFunImpl!("a" ~ exp ~ "b", "a", "b").result(a, b);
      auto reason = to!string(value) ~ " = (" ~
                    to!string(a) ~ " " ~
                    exp ~ " " ~
                    to!string(b) ~ ")";

      typeof(return) result = { value, reason };
      return result;
   }
}

unittest
{
   assert(rich!"!"(false));
   assert(rich!"!"(rich!"!="(1, 1)));

   assert(is(typeof(rich!"!"(false)) == Rich!bool));
   assert(is(typeof(rich!"!"(rich!"!="(1, 1))) == Rich!bool));
}

/// ditto
template rich(string exp)
   if(exp == "!")
{
   Rich!bool rich(T)(T a)
      if(__traits(compiles, { T a; bool b = !a; to!string(a); }))
   {
      auto value = !a;
      auto reason = to!string(value) ~ " = (!" ~ to!string(a) ~ ")";

      typeof(return) result = { value, reason };
      return result;
   }
}

/// ditto
struct Rich(Type)
   if(is(Type == bool))
{
   @property const Type value() { return _value; }
   @property const string reason() { return to!string(_reason); }

   const string toString() { return reason; }

   const Type opCast(Type)() { return value; }

   const bool opEquals(Type rhs) { return value == rhs; }
   const bool opEquals(ref const Rich!Type rhs) { return opEquals(rhs.value); }

   const int opCmp(ref const Rich!Type rhs) { return opCmp(rhs.value); }
   const int opCmp(Type rhs)
   {
      if(value < rhs) return -1;
      else if(value > rhs) return 1;
      return 0;
   }

   private Type _value;
   private string _reason;
}

private bool isBinaryOp(string op)
{
   switch(op)
   {
      case "==":
      case "!=":
      case ">":
      case ">=":
      case "<":
      case "<=":
      case "&&":
      case "||":
         return true;
      default:
         return false;
   }
}

static this()
{
   _fatal = new LogFilter(Severity.fatal, config);
   _critical = new LogFilter(Severity.critical, config);
   _error = new LogFilter(Severity.error, config);
   _warning = new LogFilter(Severity.warning, config);
   _info = new LogFilter(Severity.info, config);
}

shared static this()
{
   LogFilter._noopLogFilter = new LogFilter;

   auto args = Runtime.args;

   auto loggerConfig = FileLogger.Configuration.create();

   try loggerConfig.parseCommandLine(args);
   catch(Exception e) { /+ ignore any error +/ }

   auto logger = new FileLogger(loggerConfig);
   config = new Configuration(logger);

   try config.parseCommandLine(args);
   catch(Exception e) { /+ ignore any error +/ }
}

private LogFilter _fatal;
private LogFilter _critical;
private LogFilter _error;
private LogFilter _warning;
private LogFilter _info;

__gshared Configuration config;

version(unittest)
{
   private template isWriter(Writer)
   {
      enum bool isWriter =
         __traits(compiles, { Writer w;
                              if(!w.isOpen) w.open("name", "w");
                              w.setvbuf(1024);
                              w.writef("format", 1, true, "", 3.4);
                              w.flush();
                              w = stderr; });
   }

   // Test severity filtering
   private class TestLogger : Logger
   {
      shared void log(const ref LogMessage msg)
      {
         called = true;
         severity = msg.severity;
         message = msg.message.idup;
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

      string message;
      Severity severity;
      bool called;
      bool flushCalled;
   }

   private struct TestWriter
   {
      struct Data
      {
         size_t bufferSize;
         bool flushed;
         string mode;

         string[] lines;
      }

      @property const bool isOpen() { return (name in writers) !is null; }
      void open(string filename, in char[] mode = "")
      {
         assert(name !in writers);
         assert(filename !in writers);

         name = filename;
         writers[name] = Data.init;

         writers[name].mode = mode.idup;
      }

      void setvbuf(size_t size, int mode = 0)
      {
         assert(name in writers);
         writers[name].bufferSize = size;
      }

      void writef(S...)(S args)
      {
         assert(name in writers, name);
         auto writer = appender!string();
         formattedWrite(writer, args);
         writers[name].lines ~= writer.data;
      }

      void flush()
      {
         assert(name in writers);
         writers[name].flushed = true;
      }

      void opAssign(File rhs)
      {
         // assume it is stderr
         open("stderr file", "w");
      }

      string name;

      static void clear() { writers = null; }

      static Data[string] writers;
   }
}
