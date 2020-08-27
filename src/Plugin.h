#ifndef BRO_PLUGIN_ANALYZER_PDF
#define BRO_PLUGIN_ANALYZER_PDF

#include <plugin/Plugin.h>

namespace plugin {
namespace Analyzer_PDF {

class Plugin : public ::plugin::Plugin {
	protected:
		// Overridden from plugin::Plugin.
		plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
