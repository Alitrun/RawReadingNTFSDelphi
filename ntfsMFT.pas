(*
  Alexander Shyshko, 2009 - 2011, alitrun@gmail.com

  Main source:
  Brian Carria - Forensic Analysis of File Systems (book)


  TMFTFile
  --------------
  A class that reads MFT records from the $MFT file. Fragmentation is accounted for.

  procedure ReInitMFT: void
    Should be called before each new disk scan to set correct global variables for this module, namely gRawDisk and gMFT.
    For example, after scanning disks C and D, if the user wants to rescan them, gRawDisk might otherwise incorrectly
    contain disk F instead of C.

  function LgSizeToBytes(AValue: Shortint): integer
    In some fields, size data can be either the binary logarithm of the byte count or the number of clusters.

  ReadMFTRecHeader(AMFTNum: integer): int64
    The MFT record structure is written into the class-wide fMFTRecord: TMFTRecord. The current record number is set
    to AMFTNum in fCurrentMFTNum. The function also returns the starting offset of the MFT record relative to the MFT file.
    If the record is not found, the byte value will be INVALID_MFT_ENTRY (-1).

  SearchAttribute(AMFTNum: integer; AttrType: longword; var AttrRec: TGeneralAttrHeader): int64
    AttrRec is the standard attribute header, and the function's result is the global offset. If the attribute is not
    found, the offset will be zero.

  property StartUserRecordNum: integer
    The MFT record number from which user data begins. Anything below this is metadata and system-reserved records.

  To optimize reading, the MFT record structure is created globally within the class, as fMFTRecord.

  GetAttrDATA(AGeneralAttr: PGeneralAttr; AttrOffset: int64; var ADataRuns: TDataRunsArray): int64
    Processes the $DATA attribute. Returns the attribute's size and the cluster range list.


  TMFTEntry
  ---------------
  fDataAttrsList - Contains a list of the file's $DATA attributes (TAttribute), including the main stream and alternate
  streams. The main stream is always the first in the list (index 0) and has no name.

  property AttrsData [index: integer]: TAttribute
  Files with the ATTRIBUTE_LIST attribute are skipped as they cannot be recovered. When deleted, the NTFS driver always
  sets termination markers in non-base records, overwriting (with the marker) the pointer to the first bytes of the cluster
  range list. This makes it impossible to read the full list since its structure is dynamic, and the starting byte is
  unknown.

  TFixupMarkers (sequence array)
  These markers are used in NTFS to verify data integrity, especially for large structures exceeding sector size.
  In this context, the "structure" refers to the entire MFT record. The last two bytes of each sector are replaced with
  a special two-byte signature, while the original two bytes are copied into an array.

  See MULTI_SECTOR_HEADER: http://msdn.microsoft.com/en-us/library/bb470212(VS.85).aspx


*)

unit ntfsMFT;

interface

uses
  Windows, BaseIOClasses, NTFSStructures, NTFSAttributes, SysUtils, DLLStrings, Contnrs;

type
  TMFTEntry = class(TBaseFile)
  private
    fReadFileBytes: int64;
    fDataAttrsList: TObjectList;
    function GetDataAttr(AIndex: integer): TAttribute;
  protected
    function GetStreamsCount: integer; override;
    function GetStreamName(AIndex: integer): string; override;
    function GetStreamSize(Aindex: integer): int64; override;
  public
    destructor Destroy; override;
    function ReadFile(AStreamNum: integer; ABuf: TBufStream; AFromBegin: Boolean): Boolean; override;
    procedure Reset; override;
    property DataAttr[index: integer]: TAttribute read GetDataAttr;
  end;


  TMFTEntryStatus = (esInvalid, esNormal, esDeleted);

  TMFTFile = class(TMFTEntry)
  private
    fRawDisk        : TRawDisk;
    fStartRecordNum : integer;
    fRecordSize     : integer;
    fRecordsCount   : int64;
    fLoadedMFTNum   : int64;        {   | }
    fMFTRecord      : TMFTRecord;   { <-| }
    fAttrRec        : TGeneralAttr;
    fBootSector     : PBootSectorRec;
    fFixupMarkers   : TFixUpMarkers;
    procedure InitMFT;
    function GetStartUserRecordNum: integer;
    function LgSizeToBytes(AValue: Shortint): int64;
    function ScanFilePath(AFromEntry: int64; AChildReuseNum: integer): string;
    function ReadMFTRecHeader(AMFTNum: int64): int64;
    function ReadAttributeRec(AFromByte: int64; var ARec: TGeneralAttr): boolean;
    function SearchAttributeRec(AMFTNum: int64; AType: TAttrType; var ARec: TGeneralAttr): int64;
    function SearchAttribute(AMFTNum: int64; AType: TAttrType; var Attribute: TAttribute): boolean;
    function LoadEntry(ARec: PMFTRecord; AttrMFTOffset: int64; AEntry: TMFTEntry): boolean; overload;
    function ReplaceFixupMarkers(const ABuf; ASize: integer; AMFTFileOffset: int64): boolean;
  public
    constructor Create(ARawDisk: TRawDisk; ABootSector: PBootSectorRec);
    function LoadEntry(AMFTNum: int64; AEntry: TMFTEntry): boolean; overload;
    function GetEntryStatus(AMFTNum: int64; var AIsDir: boolean): TMFTEntryStatus;
    function ReadMFTFile(const ABuf; ASize: integer; ABodyOffset: int64; const AUseFixups: boolean = true): integer;
    property StartUserRecordNum: integer read GetStartUserRecordNum;
    property RecordsCount: int64 read fRecordsCount;
  end;


implementation


const
  INVALID_MFT_ENTRY = -1;


{ TMFTEntry }

destructor TMFTEntry.Destroy;
begin
  fDataAttrsList.Free;
  inherited;
end;

function TMFTEntry.GetStreamsCount: integer;
begin
  Result := fDataAttrsList.Count - 1;
end;

function TMFTEntry.GetStreamName(AIndex: integer): string;
begin
  Result := DataAttr[AIndex + 1].AttributeName;
end;

function TMFTEntry.GetStreamSize(Aindex: integer): int64;
begin
  Result := DataAttr[Aindex + 1].ContentSize;
end;

function TMFTEntry.GetDataAttr(AIndex: integer): TAttribute;
begin
  Assert(AIndex < fDataAttrsList.Count);
  Result := TAttribute(fDataAttrsList.List^[AIndex]);
end;

procedure TMFTEntry.Reset;
begin
  inherited;
  if fDataAttrsList <> nil then
    fDataAttrsList.Clear;
end;

function TMFTEntry.ReadFile(AStreamNum: integer; ABuf: TBufStream; AFromBegin: Boolean): Boolean;
begin
  Assert(ABuf.Position = 0);
  if AFromBegin then
    fReadFileBytes := 0;
  if AStreamNum = FILE_CONTENT_STREAM then
    AStreamNum := 0
  else
    inc(AStreamNum);

  DataAttr[AStreamNum].ReadBody(ABuf, fReadFileBytes);
  inc(fReadFileBytes, ABuf.Position);
  Result := true;
end;


{ TMFTFile }

constructor TMFTFile.Create(ARawDisk: TRawDisk; ABootSector: PBootSectorRec);
begin
  inherited Create;
  fRawDisk := ARawDisk;
  fBootSector := ABootSector;
  fRecordSize := LgSizeToBytes(ABootSector.MFTRecordSize);
  InitMFT;
end;


 {In this case, it is impossible to call methods that read the MFT record and initialize the MFT file itself.
 These records are not read relative to the disk, but from the MFT file - since it may be fragmented.
 And since its set of cluster lists (MFT file) has not yet been loaded, it is impossible to work with the records.}
procedure TMFTFile.InitMFT;
var
  vOffset     : int64;
  vAttr       : TAttribute;
  vAttrListAr : TAttrListArray;

  {Nested 1}
  function ReadMFTAttrRec(AFromByte: int64): boolean;
  begin
    fRawDisk.ReadBlockCached(fAttrRec, SizeOf(TGeneralAttr), AFromByte);
    Result := fAttrRec.AttributeType <> ATTR_END_MARKER;
  end;

  {Nested 2}
  procedure InitWithAttrList(AListArray: TAttrListArray);
  var
    vAttr: TAttribute;
    vBuf: array of byte;
    i : integer;
  begin
    vAttr := TAttribute.Create(fRawDisk, ReadMFTFile);
    try
      for i := 0 to Length(AListArray) - 1 do
      if AListArray[i].MFTEntryNum <> METAFILE_MFT then                // Located in the most basic record
      begin
        if not SearchAttribute(AListArray[i].MFTEntryNum, avData, vAttr) then Abort;
        SetLength(vBuf, vAttr.BodySize);                               // The attribute is an extension of the main $DATA
        vAttr.ReadDiskOrMFT(vBuf[0], vAttr.BodySize, vAttr.BodyStart);
        DataAttr[0].DecodeClustersList(vBuf);
      end;
    finally
      vAttr.Free;
    end;
  end;
  {end of nested}

begin
  vAttr := nil;
  vAttrListAr := nil;
  fDataAttrsList := TObjectList.Create;
  with fBootSector^ do                                                 // Start byte of MFT record
    vOffset := (MFTStartCluster * BytesPerSector * SectorsPerCluster) +
               (METAFILE_MFT * fRecordSize);

  fRawDisk.ReadBlockCached(fMFTRecord, SizeOf(TMFTRecord), vOffset);   // Write MFT file
  if fMFTRecord.Signature <> MFT_ENTRY_SIGNATURE then Abort;
  inc(vOffset, fMFTRecord.FirstAttrOffset);                            // Search for the $DATA MFT attribute

  try
    while ReadMFTAttrRec(vOffset) do
    begin
      fAttrRec.NameLength := 0;
      if vAttr = nil then
        vAttr := TAttribute.Create(fRawDisk, ReadMFTFile);
      vAttr.AssignFromRec(@fAttrRec, vOffset);
      vAttr.IsMFTOffset := false;                                     // Offset relative to disk

      case vAttr.AttrType of
        avAttrList : vAttrListAr := vAttr.GetATTRIBUTE_LIST;           // List of MFT numbers where $Dаta is located
        avData     :
          begin
            fDataAttrsList.Add(vAttr);
            fRecordsCount := vAttr.ContentSize div fRecordSize;
            if not vAttr.LoadClusters then Abort;
            vAttr := nil;
          end;
      end;
      inc(vOffset, fAttrRec.Length);
    end;
  finally
    vAttr.Free;
  end;

  if Assigned(vAttrListAr) then
    InitWithAttrList(vAttrListAr);
end;

function TMFTFile.ReadMFTFile(const ABuf; ASize: integer; ABodyOffset: int64;
  const AUseFixups: boolean = true): integer;
begin
  Result := DataAttr[0].ReadBody(ABuf, ASize, ABodyOffset);
  if AUseFixups then
    ReplaceFixupMarkers(ABuf, ASize, ABodyOffset);
end;

function TMFTFile.LgSizeToBytes(AValue: Shortint): int64;
begin
  if AValue >= 0 then
    Result := fBootSector.SectorsPerCluster * fBootSector.BytesPerSector * AValue
  else
    Result := 1 shl Abs(AValue); // 2 to the power of AValue
end;

function TMFTFile.LoadEntry(AMFTNum: int64; AEntry: TMFTEntry): boolean;
var
  vFromByte: int64;
begin
  Result := false;
  vFromByte := ReadMFTRecHeader(AMFTNum);
  if (vFromByte = INVALID_MFT_ENTRY) then exit;
  with fMFTRecord do
  begin
    if EntryNumToInt(@BaseRec) <> 0 then exit;                   // Skip non-base records
    inc(vFromByte, FirstAttrOffset);
  end;
  Result := LoadEntry(@fMFTRecord, vFromByte, AEntry);
end;

function TMFTFile.LoadEntry(ARec: PMFTRecord; AttrMFTOffset: int64; AEntry: TMFTEntry): boolean;

 {Nested}
  procedure AddDATAToEntry(Attribute: TAttribute);
  begin
    with AEntry do
    begin
      if fDataAttrsList = nil then                               // Add $Data to the entry list
        fDataAttrsList := TObjectList.Create;
      if Attribute.Name = '' then
        fDataAttrsList.Insert(0, Attribute)                      // Main $DATA is always first
      else
        fDataAttrsList.Add(Attribute);
    end;
  end;
  {End of Nested}

var
  vFileName    : TFileNameResult;
  vStdInfo     : TStdInfoResult;
  vAttribute   : TAttribute;
  vReadBytes   : integer;
begin
  Result := false;
  vAttribute := nil;
  vReadBytes := 0;
  try
    while ReadAttributeRec(AttrMFTOffset, fAttrRec) do           // Reading attributes
    begin
      inc(vReadBytes, fAttrRec.Length);
      if vReadBytes > fRecordSize then exit;                    // Recording boundary exceeded, record corrupted
      if TAttrType(fAttrRec.AttributeType) in [avStdInfo, avFileName, avData] then
      begin
        if vAttribute = nil then
          vAttribute := TAttribute.Create(fRawDisk, ReadMFTFile);
        vAttribute.AssignFromRec(@fAttrRec, AttrMFTOffset);

        case vAttribute.AttrType of
          avStdInfo  : vStdInfo:= vAttribute.GetSTD_INFO;
          avFileName : vFileName := vAttribute.GetFILE_NAME;
          avData     :
            begin
              if fAttrRec.NameLength = 0 then                    // The main $DATA is always unnamed
                AEntry.FileSize := vAttribute.ContentSize;
              AddDATAToEntry(vAttribute);
              vAttribute := nil;                                 // $DATA added to the list
            end;
        end;
      end
      else
        if TAttrType(fAttrRec.AttributeType) = avAttrList then exit; // details at the beginning of the unit

      inc(AttrMFTOffset, fAttrRec.Length);
    end;
  finally
    vAttribute.Free;
  end;

  if vFileName.FileName <> '' then
  with AEntry do
  begin
    Result := Assigned(fDataAttrsList) and (fDataAttrsList.Count > 0);
    CreatedDate := vStdInfo.CreatedDate;
    ModifiedDate := vStdInfo.ModifiedDate;
    LastAccessDate := vStdInfo.LastAccessDate;
    FileAttributes := vStdInfo.Attributes;
    FileName := vFileName.FileName;
    FilePath := ScanFilePath(vFileName.ParentRecNum, vFileName.ParentReuseCount);
  end;
end;

function TMFTFile.GetEntryStatus(AMFTNum: int64; var AIsDir: boolean): TMFTEntryStatus;
var
  vOffset: int64;
begin
  Result := esInvalid;
  vOffset := ReadMFTRecHeader(AMFTNum);
  if vOffset = INVALID_MFT_ENTRY then exit;

  AIsDir := fMFTRecord.Flags and MFT_ENTRY_IS_DIR = MFT_ENTRY_IS_DIR;
  if fMFTRecord.Flags and MFT_ENTRY_INUSE = MFT_ENTRY_INUSE then
    Result := esNormal
  else
    Result := esDeleted;
end;

function TMFTFile.GetStartUserRecordNum: integer;
var
  i          : integer;
  vFileName  : TFileNameResult;
  vAttribute : TAttribute;
begin
  if fStartRecordNum = 0 then
  begin
    vAttribute := TAttribute.Create(fRawDisk, ReadMFTFile);
    try
      for i := MFT_USER_ENTRY_STARTS to 100 do   // first hundred entries
        if SearchAttribute(i, avFileName, vAttribute) then
        begin
          vFileName := vAttribute.GetFILE_NAME;
          if (Length(vFileName.FileName) > 1) and
             (vFileName.FileName[1] <> METAFILE_CHAR) then
          begin
            fStartRecordNum := i;
            break;
          end;
        end;
    finally
      vAttribute.Free;
    end;
  end;
  Result := fStartRecordNum;
end;

function TMFTFile.ReadMFTRecHeader(AMFTNum: int64): int64;
const
  DISABLE_FIXUPS = false;
begin
  Result := (AMFTNum * fRecordSize);
  if fLoadedMFTNum = AMFTNum then exit;

  fLoadedMFTNum := NO_VALUE;
  ReadMFTFile(fMFTRecord, SizeOf(TMFTRecord), Result, DISABLE_FIXUPS);
  if fMFTRecord.Signature <> MFT_ENTRY_SIGNATURE then
    Result := INVALID_MFT_ENTRY
  else
    fLoadedMFTNum := AMFTNum;
end;

function TMFTFile.ReadAttributeRec(AFromByte: int64; var ARec: TGeneralAttr): boolean;
begin
  ReadMFTFile(ARec, SizeOf(TGeneralAttr), AFromByte);
  Result := ARec.AttributeType <> ATTR_END_MARKER;
end;

function TMFTFile.SearchAttribute(AMFTNum: int64; AType: TAttrType; var Attribute: TAttribute): boolean;
var
  vOffset: int64;
begin
  Assert(Attribute <> nil);
  vOffset := SearchAttributeRec(AMFTNum, AType, fAttrRec);
  Result := vOffset > 0;
  if Result then
    Attribute.AssignFromRec(@fAttrRec, vOffset);
end;

function TMFTFile.SearchAttributeRec(AMFTNum: int64; AType: TAttrType; var ARec: TGeneralAttr): int64;
label ContinueFromInc;
var
  vFromByte : int64;

  function IsCorrectFileNameAttr: boolean;
  var
    vNameSpace: TNameSpaces;
    vOffset: int64;
  begin
    Assert(not ARec.OutsideMFT);
    vOffset := ARec.ResidentAttr.AttributeOffset + vFromByte;    // attribute body offset
    inc(vOffset, SizeOf(TFileNameAttr) - SizeOf(TNameSpaces));   // offset relative to flag
    ReadMFTFile(vNameSpace, SizeOf(TNameSpaces), vOffset);
    Result := vNameSpace in [nsPosix, nsWin32, nsWin32AndDOS];
  end;

begin
  Result := 0;
  vFromByte := ReadMFTRecHeader(AMFTNum);
  if vFromByte = INVALID_MFT_ENTRY then exit;

  inc(vFromByte, fMFTRecord.FirstAttrOffset);
  while ReadAttributeRec(vFromByte, ARec) do
  begin
    if TAttrType(ARec.AttributeType) = AType then
    begin
      if (TAttrType(ARec.AttributeType) = avFileName) and not IsCorrectFileNameAttr then
        goto ContinueFromInc;  // I do not like "goto", but in this case it's much simplier construct
      Result := vFromByte;
      exit;
    end;
    ContinueFromInc : inc(vFromByte, ARec.Length);
  end;
end;

function TMFTFile.ScanFilePath(AFromEntry: int64; AChildReuseNum: integer): string;
var
  vAttribute: TAttribute;

  {Nested}
  function RecurseFilePath(AFromEntry: int64; AChildReuseNum: integer): string;
  var
    vOffset: int64;
    vFoundPath: boolean;
  begin
    vFoundPath := false;
    if AFromEntry = METAFILE_ROOT_DIR then exit;
    try
      vOffset := SearchAttributeRec(AFromEntry, avFileName, fAttrRec);
      if vOffset = 0 then exit;                                 // fMFTEntry is loaded into SearchAttributeRec.

      with fMFTRecord do
      begin                                                     // Does the file belong to this directory?
        if Flags and MFT_ENTRY_IS_DIR = MFT_ENTRY_IS_DIR then
          if Flags and MFT_ENTRY_INUSE = MFT_ENTRY_INUSE then
            vFoundPath := AChildReuseNum = ReuseCount           // If the folder exists
          else
            vFoundPath := AChildReuseNum = Pred(ReuseCount);    // If the folder is deleted
      end;
      if vFoundPath then
      begin
        vAttribute.AssignFromRec(@fAttrRec, vOffset);
        with vAttribute.GetFILE_NAME do
          Result := RecurseFilePath(ParentRecNum, ParentReuseCount) + FileName + '\';
      end;
    finally
      if Result = '' then
        Result := S_NTFS_UNKNOWN_PATH;
    end;
  end;
  {End of Nested}

begin
  if AFromEntry <> METAFILE_ROOT_DIR then
  begin
    vAttribute := TAttribute.Create(fRawDisk, ReadMFTFile);
    try
      Result := RecurseFilePath(AFromEntry, AChildReuseNum);
    finally
      vAttribute.Free;
    end;
  end;
  Result := fRawDisk.DiskChar + ':\' + Result;
end;

function TMFTFile.ReplaceFixupMarkers(const ABuf; ASize: integer; AMFTFileOffset: int64): boolean;
var
  vRecStart : int64;
  vMFTNum: int64;

  function LoadSequenceArray(const AMFTNum: int64): boolean;
  const
    DISABLE_FIXUPS = false;
  begin
    Result := false;
    with fMFTRecord do
    begin
      if MarkersArrayLength = 0 then exit;
      if Length( fFixupMarkers.MarkersArray ) <> MarkersArrayLength + 1 then
        SetLength( fFixupMarkers.MarkersArray, MarkersArrayLength + 1 );      // + cell per signature
      with fFixupMarkers do
      begin
        ReadMFTFile(MarkersArray[0], Length(MarkersArray) * 2, vRecStart + FixupMarkersOffset, DISABLE_FIXUPS);
        MFTNum := AMFTNum;
      end;
    end;
    Result := true;
  end;

  function WriteToBuf(ABufPos, AIndex: integer): boolean;
  var
    vPos: Pointer;
  begin
    Result := false;
    if vMFTNum <> fFixupMarkers.MFTNum then
      if not LoadSequenceArray( vMFTNum ) then exit;       // vOffset = start of record relative to MFT

    vPos := Pointer(integer(@ABuf) + ABufPos);
    with fFixupMarkers do
      Move( MarkersArray[AIndex], vPos^, SizeOf(MarkersArray[0]) );
    Result := true;
  end;

var
  vRecOffset: int64;
  vIndex: integer;
begin
  Result := false;
  vMFTNum := AMFTFileOffset div fRecordSize;
  vRecStart := ReadMFTRecHeader(vMFTNum);
  if vRecStart = INVALID_MFT_ENTRY then exit;
  vRecOffset := vRecStart;

  vIndex := 0;           // search for the number in the array and the offset of the end of the sector - 2
  repeat
    inc(vRecOffset, fRawDisk.SectorSize);
    inc(vIndex);
    if vRecOffset <= AMFTFileOffset then Continue;
    if AMFTFileOffset + ASize > vRecOffset - 2 then            // does the buffer fit into this sector?
      Result := WriteToBuf((vRecOffset - 2) - AMFTFileOffset, vIndex) // offset relative to ABuf buffer
    else
      break;
  until not Result;
end;




end.

