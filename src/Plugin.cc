#include "PDF.h"
#include "Plugin.h"
#include "file_analysis/Component.h"

namespace plugin { namespace Analyzer_PDF { Plugin plugin; } }

using namespace plugin::Analyzer_PDF;

plugin::Configuration Plugin::Configure() {
	AddComponent(new ::file_analysis::Component("PDF", ::file_analysis::PDF::Instantiate));
	plugin::Configuration config;
	config.name = "Zeek::PDF";
	config.description = "a PDF file analyzer for Zeek";
	config.version.major = 1;
	config.version.minor = 0;
#if BRO_PLUGIN_API_VERSION >= 7
	config.version.patch = 0;
#endif
	return config;
}
