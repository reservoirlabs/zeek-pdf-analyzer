#include <file_analysis/Manager.h>
#include <Type.h>
#include "PDF.h"
#include "broker/Data.h"

using namespace file_analysis;

PDF::PDF(RecordVal * args, File * file) : file_analysis::Analyzer(file_mgr->GetComponentTag("PDF"), args, file) {
    PoDoFo::PdfError::EnableDebug(false);
    PoDoFo::PdfError::EnableLogging(false);
}

PDF::~PDF() {
}

/*
 * Get PDF version string from PoDoFo object
 *
 * @param version  PoDoFo type for PDF version
 * @returns        string containing version
 */
string PDF::getVersionString(PoDoFo::EPdfVersion version) const {
    switch (version) {
        case PoDoFo::ePdfVersion_1_0:
            return "1.0";

        case PoDoFo::ePdfVersion_1_1:
            return "1.1";

        case PoDoFo::ePdfVersion_1_2:
            return "1.2";

        case PoDoFo::ePdfVersion_1_3:
            return "1.3";

        case PoDoFo::ePdfVersion_1_4:
            return "1.4";

        case PoDoFo::ePdfVersion_1_5:
            return "1.5";

        case PoDoFo::ePdfVersion_1_6:
            return "1.6";

        case PoDoFo::ePdfVersion_1_7:
            return "1.7";
    }

    // should never happen unless PoDoFo updates and we do not update this plugin
    return "UNKNOWN";
}

/*
 * Convert PoDoFo error to enum that can be sent to Bro/Zeek via an event
 *
 * @param err  PoDoFo error object
 * @returns    BifEnum that represents the same error
 */
BifEnum::PDF::Error PDF::convertError(PoDoFo::EPdfError err) const {
    switch(err) {
        case PoDoFo::ePdfError_ErrOk:
            return BifEnum::PDF::ERR_OK;

        case PoDoFo::ePdfError_TestFailed:
            return BifEnum::PDF::TEST_FAILED;

        case PoDoFo::ePdfError_InvalidHandle:
            return BifEnum::PDF::INVALID_HANDLE;

        case PoDoFo::ePdfError_FileNotFound:
            return BifEnum::PDF::FILE_NOT_FOUND;

        case PoDoFo::ePdfError_InvalidDeviceOperation:
            return BifEnum::PDF::INVALID_DEVICE_OPERATION;

        case PoDoFo::ePdfError_UnexpectedEOF:
            return BifEnum::PDF::UNEXPECTED_EOF;

        case PoDoFo::ePdfError_OutOfMemory:
            return BifEnum::PDF::OUT_OF_MEMORY;

        case PoDoFo::ePdfError_ValueOutOfRange:
            return BifEnum::PDF::VALUE_OUT_OF_RANGE;

        case PoDoFo::ePdfError_InternalLogic:
            return BifEnum::PDF::INTERNAL_LOGIC;

        case PoDoFo::ePdfError_InvalidEnumValue:
            return BifEnum::PDF::INVALID_ENUM_VALUE;

        case PoDoFo::ePdfError_PageNotFound:
            return BifEnum::PDF::PAGE_NOT_FOUND;

        case PoDoFo::ePdfError_NoPdfFile:
            return BifEnum::PDF::NO_PDF_FILE;

        case PoDoFo::ePdfError_NoXRef:
            return BifEnum::PDF::NO_XREF;

        case PoDoFo::ePdfError_NoTrailer:
            return BifEnum::PDF::NO_TRAILER;

        case PoDoFo::ePdfError_NoNumber:
            return BifEnum::PDF::NO_NUMBER;

        case PoDoFo::ePdfError_NoObject:
            return BifEnum::PDF::NO_OBJECT;

        case PoDoFo::ePdfError_NoEOFToken:
            return BifEnum::PDF::NO_EOF_TOKEN;

        case PoDoFo::ePdfError_InvalidTrailerSize:
            return BifEnum::PDF::INVALID_TRAILER_SIZE;

        case PoDoFo::ePdfError_InvalidLinearization:
            return BifEnum::PDF::INVALID_LINEARIZATION;

        case PoDoFo::ePdfError_InvalidDataType:
            return BifEnum::PDF::INVALID_DATA_TYPE;

        case PoDoFo::ePdfError_InvalidXRef:
            return BifEnum::PDF::INVALID_XREF;

        case PoDoFo::ePdfError_InvalidXRefStream:
            return BifEnum::PDF::INVALID_XREF_STREAM;

        case PoDoFo::ePdfError_InvalidXRefType:
            return BifEnum::PDF::INVALID_XREF_TYPE;

        case PoDoFo::ePdfError_InvalidPredictor:
            return BifEnum::PDF::INVALID_PREDICTOR;

        case PoDoFo::ePdfError_InvalidStrokeStyle:
            return BifEnum::PDF::INVALID_STROKE_STYLE;

        case PoDoFo::ePdfError_InvalidHexString:
            return BifEnum::PDF::INVALID_HEX_STRING;

        case PoDoFo::ePdfError_InvalidStream:
            return BifEnum::PDF::INVALID_STREAM;

        case PoDoFo::ePdfError_InvalidStreamLength:
            return BifEnum::PDF::INVALID_STREAM_LENGTH;

        case PoDoFo::ePdfError_InvalidKey:
            return BifEnum::PDF::INVALID_KEY;

        case PoDoFo::ePdfError_InvalidName:
            return BifEnum::PDF::INVALID_NAME;

        case PoDoFo::ePdfError_InvalidEncryptionDict:
            return BifEnum::PDF::INVALID_ENCRYPTION_DICT;

        case PoDoFo::ePdfError_InvalidPassword:
            return BifEnum::PDF::INVALID_PASSWORD;

        case PoDoFo::ePdfError_InvalidFontFile:
            return BifEnum::PDF::INVALID_FONT_FILE;

        case PoDoFo::ePdfError_InvalidContentStream:
            return BifEnum::PDF::INVALID_CONTENT_STREAM;

        case PoDoFo::ePdfError_UnsupportedFilter:
            return BifEnum::PDF::UNSUPPORTED_FILTER;

        case PoDoFo::ePdfError_UnsupportedFontFormat:
            return BifEnum::PDF::UNSUPPORTED_FONT_FORMAT;

        case PoDoFo::ePdfError_ActionAlreadyPresent:
            return BifEnum::PDF::ACTION_ALREADY_PRESENT;

        case PoDoFo::ePdfError_WrongDestinationType:
            return BifEnum::PDF::WRONG_DESTINATION_TYPE;

        case PoDoFo::ePdfError_MissingEndStream:
            return BifEnum::PDF::MISSING_END_STREAM;

        case PoDoFo::ePdfError_Date:
            return BifEnum::PDF::DATE;

        case PoDoFo::ePdfError_Flate:
            return BifEnum::PDF::FLATE;

        case PoDoFo::ePdfError_FreeType:
            return BifEnum::PDF::FREETYPE;

        case PoDoFo::ePdfError_SignatureError:
            return BifEnum::PDF::SIGNATURE_ERROR;

        case PoDoFo::ePdfError_MutexError:
            return BifEnum::PDF::MUTEX_ERROR;

        case PoDoFo::ePdfError_UnsupportedImageFormat:
            return BifEnum::PDF::UNSUPPORTED_IMAGE_FORMAT;

        case PoDoFo::ePdfError_CannotConvertColor:
            return BifEnum::PDF::CANNOT_CONVERT_COLOR;

        case PoDoFo::ePdfError_NotImplemented:
            return BifEnum::PDF::NOT_IMPLEMENTED;

        case PoDoFo::ePdfError_DestinationAlreadyPresent:
            return BifEnum::PDF::DESTINATION_ALREADY_PRESENT;

        case PoDoFo::ePdfError_ChangeOnImmutable:
            return BifEnum::PDF::CHANGE_ON_IMMUTABLE;

#if PODOFO_MAJOR > 0 || (PODOFO_MAJOR == 0 && PODOFO_MINOR > 9) || (PODOFO_MAJOR == 0 && PODOFO_MINOR == 9 && PODOFO_REVISION >= 5)
        case PoDoFo::ePdfError_NotCompiled:
            return BifEnum::PDF::NOT_COMPILED;

        case PoDoFo::ePdfError_OutlineItemAlreadyPresent:
            return BifEnum::PDF::OUTLINE_ITEM_ALREADY_PRESENT;

        case PoDoFo::ePdfError_NotLoadedForUpdate:
            return BifEnum::PDF::NOT_LOADED_FOR_UPDATE;

        case PoDoFo::ePdfError_CannotEncryptedForUpdate:
            return BifEnum::PDF::CANNOT_ENCRYPTED_FOR_UPDATE;
#endif

#if PODOFO_MAJOR > 0 || (PODOFO_MAJOR == 0 && PODOFO_MINOR > 9) || (PODOFO_MAJOR == 0 && PODOFO_MINOR == 9 && PODOFO_REVISION >= 6)
        case PoDoFo::ePdfError_BrokenFile:
            return BifEnum::PDF::BROKEN_FILE;
#endif

        case PoDoFo::ePdfError_Unknown:
            return BifEnum::PDF::UNKNOWN;
    }

    // should never happen unless PoDoFo updates and we do not update this plugin
    return BifEnum::PDF::UNKNOWN;
}

/*
 * Invoked whenever a new data block arrives
 *
 * @param data  pointer to an array of incoming bytes
 * @param len   is the amount of incoming bytes
 * @returns boolean indicating if analysis is still valid
 */
bool PDF::DeliverStream(const u_char * data, uint64 len) {
    if (pdf_data.size() + len > BifConst::PDF::MAX_SIZE) {
        BifEvent::generate_pdf_too_large((analyzer::Analyzer *)this, GetFile()->GetVal()->Ref());
        return false;
    }

    pdf_data.append(reinterpret_cast<const char *>(data), len);

    return true;
}


/*
 * Invoked whenever bytes go missing. Analysis will almost never work properly if this happens
 *
 * @param offset    pointer to an array of incoming bytes
 * @param len       is the amount of incoming bytes
 * @returns boolean indicating if analysis is still valid
 */
bool PDF::Undelivered(uint64 offset, uint64 len) {
    return false;
}


/*
 * Invoked whenever a new data block arrives
 *
 * @returns boolean indicating if analysis is still valid
 */
bool PDF::EndOfFile() {
    bool ret = AnalyzePDF(pdf_data);
    pdf_data.clear();
    return ret;
}


/*
 * Analyze a PDF file from raw bytes
 *
 * @param buf Bytes containing PDF buffer
 * @returns boolean indicating if analysis is still valid
 */
bool PDF::AnalyzePDF(const string buf) {
    try {
        // load document from filled buffer adjusting call per PoDoFo version
        #if PODOFO_MAJOR > 0 || (PODOFO_MAJOR == 0 && PODOFO_MINOR > 9) || (PODOFO_MAJOR == 0 && PODOFO_MINOR == 9 && PODOFO_REVISION >= 6)
        doc.LoadFromBuffer(reinterpret_cast<const char *>(buf.data()), buf.size());
#else
        doc.Load(reinterpret_cast<const char *>(buf.data()), buf.size(), false);
#endif

    } catch (const PoDoFo::PdfError & err) {
        // send error to Bro scripts
        BifEvent::generate_pdf_error((analyzer::Analyzer *)this, GetFile()->GetVal()->Ref(), BifType::Enum::PDF::Error->GetVal(convertError(err.GetError())));
    }

    // bail if document failed to load
    if (!doc.IsLoaded())
        return false;

    // get names tree for checking features used
    PoDoFo::PdfNamesTree * names = doc.GetNamesTree();
    if (!names)
	return false;

    // fixes bug where malformed pdf has this structure missing
    PoDoFo::PdfObject* object = doc.GetCatalog();
    if (!object)
        return false;

    // get list of embedded files
    PoDoFo::PdfDictionary emb_dict;
    names->ToDictionary(PoDoFo::PdfName("EmbeddedFiles"), emb_dict);
    bool files = !emb_dict.GetKeys().empty();

    // get list of embedded javascript
    PoDoFo::PdfDictionary js_dict;
    names->ToDictionary(PoDoFo::PdfName("JavaScript"), js_dict);
    bool javascript = !js_dict.GetKeys().empty();
    
    // create allowed record type
    RecordVal * allowed = new RecordVal(BifType::Record::PDF::Allowed);

    // fill in record with TYPE_BOOL values
    allowed->Assign(0, val_mgr->GetBool(doc.IsPrintAllowed())); 
    allowed->Assign(1, val_mgr->GetBool(doc.IsEditAllowed()));
    allowed->Assign(2, val_mgr->GetBool(doc.IsCopyAllowed()));
    allowed->Assign(3, val_mgr->GetBool(doc.IsEditNotesAllowed()));
    allowed->Assign(4, val_mgr->GetBool(doc.IsFillAndSignAllowed()));
    allowed->Assign(5, val_mgr->GetBool(doc.IsAccessibilityAllowed()));
    allowed->Assign(6, val_mgr->GetBool(doc.IsDocAssemblyAllowed()));
    allowed->Assign(7, val_mgr->GetBool(doc.IsHighPrintAllowed()));

    // Create a table value (no yield meaning it is a set)
    TypeList * ext_tl = new TypeList(zeek::BifType::Record::PDF::Extension);
    auto set_index = zeek::make_intrusive<TypeList>(ext_tl->AsTypeList()->GetPureType());
    set_index->Append(zeek::BifType::Record::PDF::Extension);
    auto set_index_intrusive = zeek::make_intrusive<SetType>(std::move(set_index), nullptr);
    auto extensions = zeek::make_intrusive<zeek::TableVal>(std::move(set_index_intrusive));

    for (const PoDoFo::PdfExtension & ext : doc.GetPdfExtensions()) {
        // create extension record type
        RecordVal * extension = new RecordVal(BifType::Record::PDF::Extension);

        // fill in namespace, base version, and extension level
        extension->Assign(0, new StringVal(ext.getNamespace()));
        extension->Assign(1, new StringVal(getVersionString(ext.getBaseVersion())));
        extension->Assign(2, val_mgr->GetInt(ext.getLevel()));

        // assign extension to set (yield is nullptr because this is a set)
        extensions->Assign(extension, nullptr);
    }

    // get body text of document
    string pdfBody; 
    try {
        if(!ExtractBody(&doc, pdfBody) || pdfBody.length() == 0) {
            fprintf(stderr, "Failed to extract pdf body\n");
            pdfBody = "";
        }
    } catch (const PoDoFo::PdfError & err) {
        // send error to Bro scripts
        BifEvent::generate_pdf_error((analyzer::Analyzer *)this, GetFile()->GetVal()->Ref(), BifType::Enum::PDF::Error->GetVal(convertError(err.GetError())));
    }
    
    string pdfURLs; 
    ExtractURLs(&doc, pdfURLs);
    if(pdfURLs.length() == 0) {
        fprintf(stderr, "No embedded URLs\n");
    }

    string pdfEmbFiles;
    ExtractEmbFiles(names, pdfEmbFiles);
    if(pdfEmbFiles.length() == 0) {
        fprintf(stderr, "No embedded files\n");
    }

    // create info record
    RecordVal * info = new RecordVal(BifType::Record::PDF::Info);

    // assign values
    info->Assign(0, new StringVal(getVersionString(doc.GetPdfVersion())));
    info->Assign(1, val_mgr->GetCount(doc.GetPageCount()));
    info->Assign(2, val_mgr->GetBool(files));
    info->Assign(3, val_mgr->GetBool(javascript));
    info->Assign(4, val_mgr->GetBool(doc.GetEncrypted()));
    info->Assign(5, val_mgr->GetBool(doc.IsLinearized()));
    info->Assign(6, allowed);
    info->Assign(7, extensions);
    info->Assign(8, new StringVal(pdfBody));
    info->Assign(9, new StringVal(pdfURLs));
    info->Assign(10, new StringVal(pdfEmbFiles));

    // send event to Bro scripts
    BifEvent::generate_pdf_info((analyzer::Analyzer *)this, GetFile()->GetVal()->Ref(), info);

    return true;
}


/*
 * Given a PDF document, extract the names of the embedded files
 *
 * @param doc  Pointer to names tree
 * @param embFiles String we are appending filenames to
 */
void PDF::ExtractEmbFiles(PoDoFo::PdfNamesTree* tree, string & embFiles) {
    PoDoFo::PdfDictionary dict;
    tree->ToDictionary(PoDoFo::PdfName("EmbeddedFiles"), dict);
    
    const PoDoFo::TKeyMap& keys = dict.GetKeys();
    PoDoFo::TCIKeyMap it = keys.begin();

    while(it != keys.end()) {
        embFiles = embFiles + (*it).first.GetName() + " ";
        ++it;
    }
}

/*
 * Given a PDF document, extract all the embedded urls
 *
 * @param doc  Pointer to document buffer
 * @param urls String we are appending urls to
 */
void PDF::ExtractURLs(PoDoFo::PdfMemDocument* doc, string & urls) {
    PoDoFo::PdfPage* currentPage;
    PoDoFo::PdfAnnotation* currentAnnot;
    
    int annotCount;
    int pageCount = doc->GetPageCount();

    for (int i = 0; i < pageCount; i++) {
        currentPage = doc->GetPage(i);
        annotCount = currentPage->GetNumAnnots();

        for (int j = 0; j < annotCount; j++) {
            currentAnnot = currentPage->GetAnnotation(j);
            if (currentAnnot->GetType() == PoDoFo::ePdfAnnotation_Link
             && currentAnnot->HasAction() && currentAnnot->GetAction()->HasURI()) {
                urls = urls + " " + currentAnnot->GetAction()->GetURI().GetStringUtf8();
            }
        }
    }
}

/*
 * Given a PDF document, extract all the text in the body
 *
 * @param doc  Pointer to document buffer
 * @param urls String we are appending text to
 * @returns boolean indicating if analysis still valid
 */
bool PDF::ExtractBody(PoDoFo::PdfMemDocument* doc, string & body) {
    std::stack<PoDoFo::PdfVariant> stack;
    double dCurPosX = 0.0;
    double dCurPosY = 0.0;
    bool bTextBlock = false;
    const char* token = nullptr;
    PoDoFo::PdfFont* pCurFont   = nullptr;
    PoDoFo::PdfVariant var;
    PoDoFo::EPdfContentsType type;

    for (int pn = 0; pn < doc->GetPageCount(); ++pn) {
        PoDoFo::PdfPage* page = doc->GetPage(pn);
    
        if (!page) {
            return false;
        }    

        PoDoFo::PdfContentsTokenizer tok(page);
   
        while(tok.ReadNext(type, token, var)) {
            if(type == PoDoFo::ePdfContentsType_Keyword) {
                // support 'l' and 'm' tokens
                if(strcmp( token, "l" ) == 0 || strcmp( token, "m" ) == 0) {
                    if(stack.size() == 2) {
                        dCurPosX = stack.top().GetReal();
                        stack.pop();
                        dCurPosY = stack.top().GetReal();
                        stack.pop();
                    } else {
                        while(!stack.empty())
                            stack.pop();
                    }
                } else if (strcmp( token, "BT" ) == 0) // BT does not reset font
                    bTextBlock   = true;     

                if(bTextBlock) {
                    if( strcmp( token, "Tf" ) == 0 ) { 
                        if( stack.size() < 2 ) {
                            // font warning
                            pCurFont = NULL;
                            continue;
                        }

                        stack.pop();
                        PoDoFo::PdfName fontName = stack.top().GetName();
                        PoDoFo::PdfObject* pFont = page->GetFromResources( PoDoFo::PdfName("Font"), fontName );
                        if( !pFont ) {
                            return false;
                        }
                        
                        pCurFont = doc->GetFont( pFont );
                    } else if(strcmp(token, "Tj") == 0 || strcmp(token, "'") == 0) {
                        if(stack.size() < 1)
                            continue;

                        AddTextElement(pCurFont, stack.top().GetString(), body);
                        stack.pop();
                    } else if( strcmp( token, "\"" ) == 0 ) {
                        if( stack.size() < 3 ) {
                            while(!stack.empty())
                                stack.pop();

                            continue;
                        }

                        AddTextElement(pCurFont, stack.top().GetString(), body);
                        stack.pop();
                        stack.pop(); // remove char spacing from stack
                        stack.pop(); // remove word spacing from stack
                    } else if( strcmp( token, "TJ" ) == 0 ) {
                        if( stack.size() < 3 )
                            continue;

                        PoDoFo::PdfArray array = stack.top().GetArray();
                        stack.pop();
                        
                        for( int i=0; i<static_cast<int>(array.GetSize()); i++) 
                            if( array[i].IsString() || array[i].IsHexString() )
                                AddTextElement(pCurFont, array[i].GetString(), body);
                    }
                }
            } else if (type == PoDoFo::ePdfContentsType_Variant) {
                stack.push(var);
            } else {
                // Impossible; type must be keyword or variant
                return false;
            }
        }
    }

    return true;
}

/*
 * Given a hex string and font from PDF encoding, convert to UTF-8 and append to buf
 *
 * @param pCurFont PoDoFo font that we extrapolated from document encoding
 * @param rString  Hex string that we are trying to convert
 * @param buf      String containing PDF body that we are appending to
 */
void PDF::AddTextElement(PoDoFo::PdfFont* pCurFont, const PoDoFo::PdfString & rString, string & buf ) {
    if(!pCurFont || !pCurFont->GetEncoding()) { 
        return;
    }

    PoDoFo::PdfString unicode = pCurFont->GetEncoding()->ConvertToUnicode( rString, pCurFont );
    buf = buf + unicode.GetStringUtf8().c_str();
}
