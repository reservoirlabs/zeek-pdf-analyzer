module PDF;

export {

## Provides metadata on PDF document permissions
	type Allowed: record {
		printing: bool;
		editing: bool;
		copying: bool;
		note_editing: bool;
		fill_and_sign: bool;
		accessibility: bool;
		doc_assembly: bool;
		high_printing: bool;
	};

## Provides PDF extension info
	type Extension: record {
		namespace: string;
		base: string;
		level: int;
	};

## Provides the rest of the headers and plain text body of a PDF document
	type Info: record {
		version: string;
		pages: count;
		files: bool;
		javascript: bool;
		encrypted: bool;
		linearized: bool;
		allowed: Allowed;
		extensions: set[Extension];
		body: string &optional;
        urls: string &optional;
        embfiles: string &optional;
	};

## Possible PoDoFo error types when manipulating a PDF document
	type Error: enum {
		ERR_OK,
		TEST_FAILED,
		INVALID_HANDLE,
		FILE_NOT_FOUND,
		INVALID_DEVICE_OPERATION,
		UNEXPECTED_EOF,
		OUT_OF_MEMORY,
		VALUE_OUT_OF_RANGE,
		INTERNAL_LOGIC,
		INVALID_ENUM_VALUE,
		PAGE_NOT_FOUND,
		NO_PDF_FILE,
		NO_XREF,
		NO_TRAILER,
		NO_NUMBER,
		NO_OBJECT,
		NO_EOF_TOKEN,
		INVALID_TRAILER_SIZE,
		INVALID_LINEARIZATION,
		INVALID_DATA_TYPE,
		INVALID_XREF,
		INVALID_XREF_STREAM,
		INVALID_XREF_TYPE,
		INVALID_PREDICTOR,
		INVALID_STROKE_STYLE,
		INVALID_HEX_STRING,
		INVALID_STREAM,
		INVALID_STREAM_LENGTH,
		INVALID_KEY,
		INVALID_NAME,
		INVALID_ENCRYPTION_DICT,
		INVALID_PASSWORD,
		INVALID_FONT_FILE,
		INVALID_CONTENT_STREAM,
		UNSUPPORTED_FILTER,
		UNSUPPORTED_FONT_FORMAT,
		ACTION_ALREADY_PRESENT,
		WRONG_DESTINATION_TYPE,
		MISSING_END_STREAM,
		DATE,
		FLATE,
		FREETYPE,
		SIGNATURE_ERROR,
		MUTEX_ERROR,
		UNSUPPORTED_IMAGE_FORMAT,
		CANNOT_CONVERT_COLOR,
		NOT_IMPLEMENTED,
		DESTINATION_ALREADY_PRESENT,
		CHANGE_ON_IMMUTABLE,
		NOT_COMPILED,
		BROKEN_FILE,
		OUTLINE_ITEM_ALREADY_PRESENT,
		NOT_LOADED_FOR_UPDATE,
		CANNOT_ENCRYPTED_FOR_UPDATE,
		UNKNOWN,
	};
}
