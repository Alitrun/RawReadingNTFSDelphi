(*
Alexander Shyshko, 2009 - 2010, alitrun@gmail.com

Main source:
Brian Carria - Forensic Analysis of File Systems (book)

*)


unit ntfsStructures;

interface

uses
  Windows;

const
  MFT_ENTRY_SIGNATURE   : array [0..3] of char = ('F','I','L','E');
  MFT_ENTRY_EMPTY       = 0;
  MFT_ENTRY_INUSE       = $01;
  MFT_ENTRY_IS_DIR      = $02;
  MFT_USER_ENTRY_STARTS = 24;

  METAFILE_CHAR         = '$';
  METAFILE_MFT          = 0;
  METAFILE_ROOT_DIR     = 5;
  METAFILE_BITMAP       = 6;

  ATTR_END_MARKER       = $ffffffff;

  ATTR_RESIDENT         = 0;
  ATTR_NOT_RESIDENT     = $01;
  ATTR_COMPRESSED       = $0001;
  ATTR_ENCRYPTED        = $4000;
  ATTR_SPARSE           = $8000;

  NO_VALUE              = -1;

type
  {$Z2}
  TAttrType =                       {Always Resident:}
  (
   avStdInfo            = $10,      {+}
   avAttrList           = $20,      {+}
   avFileName           = $30,      {+}
   avSecurityDesciptor  = $50,      {-}
   avData               = $80,      {-}
   avIndexRoot          = $90,      {+}    {For folders only}
   avIndexAllocation    = $A0,      {+}
   avBitmap             = $B0       {-}
  );

  {$Z1}
  TNameSpaces =
  (
   nsPosix       = 0,
   nsWin32       = 1,
   nsDOS         = 2,
   nsWin32AndDOS = 3
   );

  PBootSectorRec = ^TBootSectorRec;
  TBootSectorRec = packed record                          {Necessity:}
    JmpBoot             : array [0..2] of byte;           {-}
    OEMName             : array [0..7] of char;           {-}  {'NTFS'}
    BytesPerSector      : word;                           {+}
    SectorsPerCluster   : byte;                           {+}
    Unused              : array [0..6] of byte;           {-}
    MediaDescriptor     : byte;                           {-}  {F8 - hard drive}
    Unused2             : word;                           {-}
    SectorsPerTrack     : word;                           {-}
    HeadCount           : word;                           {-}
    Unused3             : array [0..11] of byte;          {-}
    TotalSectors        : int64;                          {+}
    MFTStartCluster     : int64;                          {+}
    MFTMirrStartCluster : int64;                          {-}
    MFTRecordSize       : Shortint;                       {+}  {Negative number - binary logarithm of number of bytes. Positive - number of clusters}
    Unused4             : array [0..2] of byte;           {-}
    IndexRecordSize     : Shortint;                       {+}  {see MFTRecordSize}
   {Unused5             : array [0..2] of byte;           {-}
   {SerialNumber        : int64;                          {-}
  end;

  PEntryNumber = ^TEntryNumber;
  TEntryNumber = packed record
    RecNumLow       : longword;
    RecNumHi        : word;
    RecReuseCount   : word;
  end;

  PMFTRecord = ^TMFTRecord;
  TMFTRecord = packed record
    Signature           : array [0..3] of char;           {-} {'FILE'}
    FixupMarkersOffset  : word;                           {+}
    MarkersArrayLength  : word;                           {+} {Record integrity checking markers (2 bytes each)}
    LogFileLSN          : int64;                          {-}
    ReuseCount          : word;                           {-}
    HardLinkCount       : word;                           {-}
    FirstAttrOffset     : word;                           {+}
    Flags               : word;                           {+} {Record is used, is a directory}
    RealRecSize         : longword;                       {+}
    AllocatedRecSize    : longword;                       {+}
    BaseRec             : TEntryNumber;                   {-} {In base record = 0}
    NextAttributeID     : word;                           {-} {The not yet created (next) attribute will receive this ID}
  end;

  TGeneralResidentAttr = packed record
    Size                : longword;                       {+}
    AttributeOffset     : word;                           {+}
    IndexedFlag         : byte;                           {?}
    Padding             : byte;                           {?}
  end;

  TGeneralNonResidentAttr = packed record
    StartVCN             : int64;                         {+}
    LastVCN              : int64;                         {+}
    DataRunsOffset       : word;                          {+}
    CompressionBlockSize : word;                          {+} {Size = 2^x clusters. 0 - not compressed}
    NotUsed              : integer;                       {-}
    AllocatedAttrSize    : int64;                         {-} {Rounded to cluster size}
    RealAttrSize         : int64;                         {+}
    InitializedAttrSize  : int64;                         {-}
  end;

  PGeneralAttr = ^TGeneralAttr;
  TGeneralAttr = packed record
    AttributeType         : longword;                     {+}
    Length                : longword;                     {+} {Including this record}
    OutsideMFT            : bytebool;                     {+} {Non-resident attribute flag}
    NameLength            : byte;                         {+}
    NameOffset            : word;                         {+}
    Flags                 : word;                         {+} {Compressed, Encrypted, Sparse}
    AttributeID           : word;                         {+} {Unique attribute number in the current MFT record}
    case byte of
      0: (ResidentAttr    : TGeneralResidentAttr);
      1: (NonResidentAttr : TGeneralNonResidentAttr);
  end;

  TFileNameAttr = packed record
    ParentRec             : TEntryNumber;                 {-}
    CreateDate            : int64;                        {-}
    ModifiedDate          : int64;                        {-}
    MFTModifiedDate       : int64;                        {-}
    LastAccessDate        : int64;                        {-}
    AllocatedFileSize     : int64;                        {-}
    RealFileSize          : int64;                        {-} {Updated only in folder indexes}
    Flags                 : longword;                     {-}
    ReparsePointBufSize   : longword;                     {-}
    FileNameLength        : byte;                         {+} {In characters}
    FileNameSpace         : TNameSpaces;                  {+} {Namespace}
  end;

  TStdInfoAttr = packed record
    CreateDate            : TFileTime;                    {-}
    ModifiedDate          : TFileTime;                    {-}
    MFTModifiedDate       : TFileTime;                    {-}
    LastAccessDate        : TFileTime;                    {-}
    Flags                 : longword;                     {-}
    MaxFileVersionNum     : longword;                     {-} {Maximum number of file versions}
    FileVersion           : longword;                     {-} {Version of this file}
    ClassID               : longword;                     {-}
    OwnerID               : longword;                     {-} {Used in $Quota}
    SecurityID            : longword;                     {-} {Used to index the $Secure file. Not to be confused with the SID code}
    QuotaCharged          : int64;                        {-} {Number of bytes the file uses from disk quota}
    UpdateSequenceNumber  : int64;                        {-} {Index in file $UsnJrnl}
  end;

  TAttrListElement = packed record
    AttributeType         : longword;                     {+}
    Length                : word;                         {+}
    NameLength            : byte;                         {+}
    NameOffset            : byte;                         {+}
    StartVCN              : int64;                        {+} {If the attribute description requires > 1 MFT record}
    MFTEntryNum           : TEntryNumber;                 {+}
    AttributeID           : word;                         {+}
  end;


  TFixUpMarkers = record
    MFTNum         : int64;
    MarkersArray   : array of word;
  end;


  function EntryNumToInt(ARec: PEntryNumber): int64;
  procedure ConvertToSignValue(var AValue: int64; ABytesCount: integer);
  function DecompressLZNT1(const ASrcBuf; ASrcSize: integer; const ADestBuf; ADestSize: integer): integer;

implementation

uses SysUtils;

 function RtlDecompressBuffer(
     CompressionFormat : Word;
     UncompressedBuffer : PUCHAR;
     UncompressedBufferSize : ULONG;
     CompressedBuffer : PUCHAR;
     CompressedBufferSize : ULONG;
     FinalUncompressedSize : PULONG
     ) : Cardinal; stdcall; external 'ntdll.dll' name 'RtlDecompressBuffer';


function EntryNumToInt(ARec: PEntryNumber): int64;
begin
  with ARec^ do
    Result := (int64(RecNumHi) shl 32) or RecNumLow;
end;

procedure ConvertToSignValue(var AValue: int64; ABytesCount: integer);
const
  SIGN_1BYTES = $FFFFFFFFFFFFFF00;
  SIGN_2BYTES = $FFFFFFFFFFFF0000;
  SIGN_3BYTES = $FFFFFFFFFF000000;
  SIGN_4BYTES = $FFFFFFFF00000000;
  SIGN_5BYTES = $FFFFFF0000000000;
  SIGN_6BYTES = $FFFF000000000000;
  SIGN_7BYTES = $FF00000000000000;
var
  vBit: int64;
begin
  Assert(ABytesCount <= SizeOf(int64));
  if ABytesCount <= 7 then
  begin
    vBit := AValue shr (ABytesCount * 8 - 1);       // look at the most significant bit
    if vBit = 0 then exit;                          // is included in the signed range of a number of a given size
  end;
  case ABytesCount of
    1: AValue := AValue or SIGN_1BYTES;
    2: AValue := AValue or SIGN_2BYTES;
    3: AValue := AValue or SIGN_3BYTES;
    4: AValue := AValue or SIGN_4BYTES;
    5: AValue := AValue or SIGN_5BYTES;
    6: AValue := AValue or SIGN_6BYTES;
    7: AValue := AValue or SIGN_7BYTES;
  end;
end;

function DecompressLZNT1(const ASrcBuf; ASrcSize: integer; const ADestBuf; ADestSize: integer): integer;
const
  COMPRESSION_FORMAT_LZNT1 : word = $0002;
begin
  Result := 0;
  RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, @ADestBuf, ADestSize,
                      @ASrcBuf, ASrcSize, @Result);
  Assert(Result <= ADestSize);
end;

end.

