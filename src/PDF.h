#ifndef ANALYZER_PDF_H
#define ANALYZER_PDF_H

#include <string>
#include <stack>

#include <Val.h>

#include <file_analysis/Analyzer.h>
#include <file_analysis/File.h>

#include "events.bif.h"
#include "pdf.bif.h"

// fix macro collisions
#pragma push_macro("IsBool")
#undef IsBool
#pragma push_macro("IsString")
#undef IsString
#include <podofo.h>

namespace file_analysis {
    class PDF : public file_analysis::Analyzer {
        public:
            virtual ~PDF();

            static file_analysis::Analyzer * Instantiate(RecordVal * args, File * file) {
                return new PDF(args, file);
            }
            
            bool AnalyzePDF(const string buf);

            virtual bool Undelivered(uint64 offset, uint64 len);
            virtual bool DeliverStream(const u_char * data, uint64 len);
            virtual bool EndOfFile();

        protected:
            PDF(RecordVal * args, File * file);

            string getVersionString(PoDoFo::EPdfVersion version) const;
            BifEnum::PDF::Error convertError(PoDoFo::EPdfError err) const;

            string pdf_data;
            PoDoFo::PdfMemDocument doc;

            bool ExtractBody(PoDoFo::PdfMemDocument* doc, string & body);
            void ExtractURLs(PoDoFo::PdfMemDocument* doc, string & urls);
            void ExtractEmbFiles(PoDoFo::PdfNamesTree* tree, string & embFiles);
            void AddTextElement(PoDoFo::PdfFont* pCurFont, const PoDoFo::PdfString & rString, string & buf );
    };
}

#endif
