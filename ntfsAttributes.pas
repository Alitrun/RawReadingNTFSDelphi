(*

Alexander Shyshko, 2009 - 2010, alitrun@gmail.com

Main source:
Brian Carria - Forensic Analysis of File Systems (book)


TAttribute
-----------

ReadBody(ABuf: TBufStream; ABodyOffset: int64): void;
ReadBody(const ABuf; ABufSize: integer; ABodyOffset: int64): integer;
Reads the attribute's content, usually only for the DATA attribute.
  The second method returns the number of bytes read. When reading compressed attributes, the buffer size is adjusted
  to match the size of the compressed block (in the first method), regardless of the initial size. This adjustment is
  necessary to decompress the block before reading, as compressed blocks typically equal 16 clusters.
  Therefore, compressed files must always be read from the beginning. Using the second method will return the data in
  compressed form, as it is stored on the clusters.

LoadClusters: boolean
  Reads the series of cluster ranges (known as DataRuns) and saves them in a readable format.

RegroupClustersCompressed: void
  Rearranges the cluster lists for compressed files. For regular files, this method is not called. Cluster lists are
  divided into 16-cluster blocks to determine whether a block is compressed. Each block is added to the standard DataRuns
  array, where the ClusterType field of each array cell indicates the cluster type (compressed, sparse, or normal).
  If the file is not marked as compressed, these fields remain as cdUnknown.

fBodyStart: int64
  For resident attributes, this is the offset to the attribute content (e.g., $DATA for files/streams).
  For non-resident attributes, it is the offset to the cluster range list (DataRuns). There are two possible scenarios,
  depending on the fIsMFTOffset flag. 1. An offset in bytes relative to the disk volume. 2. Relative to the MFT file.
  The first is used when loading the MFT, and the second is for regular MFT records.

fBodySize: int64
  The size of the attribute, excluding the standard header. For non-resident attributes, this is the size of the cluster
  range list; for resident attributes, it matches the content size (fContentSize).

fContentSize: int64
  For non-resident attributes, this is the size of the content stored on clusters (e.g., for $DATA, it would be the file
  size). For resident attributes, it is identical to fBodySize.

fLastClusterIndex: int64
  Used when reading cluster lists. For regular (non-compressed) clusters, this variable stores the index of the cluster
  in the array whose content is in the current buffer (fClusterBuf), so the cluster does not need to be re-read
  (common when only part of a cluster is read). For compressed clusters, it holds the index of the last cluster read.
  Compressed clusters are read in 16-cluster blocks, meaning this variable will always hold the last cluster of a recently
  read block. Even if clusters are not compressed, they are read in these blocks, provided the attribute is marked
  as compressed. This ensures subsequent reads start with a new block.

fComprsBlockSize: integer
  The compression block size in bytes, typically equal to 16 clusters.


TDataRuns
-----------

Cluster[index: longword]: int64
  Calculates the cluster index in the array. The array consists of cluster ranges—starting cluster and the length of
  clusters after it—significantly reducing memory usage. For example, storing each cluster individually would require
  a 4 MB int64 array (524,288 cells) for a 1 GB file with 2 KB clusters. If there was a prior access to a neighboring index,
  the index is calculated based on saved values instead of scanning the entire array. The array can be visualized as a table,
  where columns represent the main indices (starting clusters), and rows in a column represent the number of clusters
  after the starting one. The starting cluster is excluded from this interval.

OffsetToIndex(var AFileOffset: int64): longword
  Calculates the cluster index in Clusters[i] from AFileOffset (offset relative to the attribute content) and the offset
  within the cluster. The offset is returned via the AFileOffset variable.

RegroupClustersCompressed: void
  If the file is compressed, this method produces a regrouped DataRuns array without sparse clusters. The original cluster
  list is divided into 16-cluster blocks (block size may vary, depending on the attribute's field). It determines whether
  the block is compressed based on the presence of virtual clusters (sparse) or normal clusters. A block is compressed if
  it contains both virtual and normal clusters. If all clusters are virtual, the block is marked as sparse, and its data
  will be filled with zeros. Blocks without virtual clusters are uncompressed. During regrouping, overlapping DataRuns
  fragments are handled. For example, consider cluster fragments (counts): 15, 3, 14. Fragments 15 and 3 are combined into
  one group (15 clusters from the first fragment and 1 from the second, making 16). The remaining 2 clusters combine with
  the 14-cluster fragment, forming another 16-cluster block. The regrouped fragments become:

1. 15 (original offset)
2. 1 (original offset)
3. 2 (offset relative to the previous cluster in this fragment + original from point 2)
Regrouping ensures seamless access to any fragment/cluster while determining whether the data is compressed, sparse,
or uncompressed.

 *)

unit ntfsAttributes.pas_;

interface

uses
  ntfsStructures, BaseIOClasses, Windows, SysUtils, AdditionalFunc;

type
  TReadMFTFunc = function (const ABuf; ASize: integer; ABodyOffset: int64;
                           const AUseFixups: boolean = true): integer of object;

  TFileNameResult = record
    ParentRecNum     : int64;
    ParentReuseCount : integer;
    FileName         : string;
  end;

  TStdInfoResult = record
    CreatedDate    : TDateTime;
    ModifiedDate   : TDateTime;
    LastAccessDate : TDateTime;
    Attributes     : longword;
  end;

  TClusterType = (ctUnknown, ctNormal, ctCompressed, ctSparsed);

  TDataRunRec = record
    StartCluster        : int64;
    ClustersCount       : longword;      // includes the start
    ClusterType         : TClusterType;  // For normal (non-compressed) always Unknown
    CompressBlockEnd    : boolean;       // (only when compressed) This fragment ends the compression block.
  end;                                   // Accordingly, the last cluster in this fragment is the last cluster of the block
                                         // this flag is necessary because the fragment can be < the block size

  TClusterRec = record
    StartCluster        : int64;
    ClusterType         : TClusterType;
    LastInCompressBlock : boolean;
  end;

  TDataRuns = class
  private
    fClusterSize   : integer;
    fArIndex       : longword;
    fArIndexOffset : longword;
    fCalcIndex     : longword;
    fClustersCount : longword;
    function GetCluster(AIndex: longword): TClusterRec;
  public
    fDataRunsAr    : array of TDataRunRec;
    constructor Create(AClusterSize: integer);
    procedure AddFragment(AClusterOffset, AClustersCount: int64);
    function OffsetToIndex(AFileOffset: int64; var AClusterOffset: integer): longword;
    procedure Reset;
    property Cluster[index: longword]: TClusterRec read GetCluster; default;
    property ClustersCount: longword read fClustersCount;
  end;


  TAttrListArrayElement = record
    MFTEntryNum: int64;
    AttrType: TAttrType;
  end;
  TAttrListArray = array of TAttrListArrayElement;

  TAttribute = class
  private
    fType            : TAttrType;
    fIsResident      : boolean;
    fIsCompressed    : boolean;
    fBodySize        : integer;
    fBodyStart       : int64;
    fContentSize     : int64;
    fName            : string;
    fRawDisk         : TRawDisk;
    fDataRuns        : TDataRuns;
    fReadMFTFunc     : TReadMFTFunc;
    fLastClusterIndex: int64;
    fClusterBuf      : array of char;
    fComprsBlockSize : integer;
    function GetClustersList: TDataRuns;
    procedure RegroupClustersCompressed;
    procedure ReadCluster(var ABuf; AIndex: longword);
  protected
    function ReadResident(const ABuf; ASize: integer; ABodyOffset: integer): integer;
    function ReadNonResident(const ABuf; ASize: integer; ABodyOffset: int64): integer;
    function ReadCompressed(const ABuf; ASize: integer; AFromBegin: boolean): integer;
  public
    IsMFTOffset: boolean;
    constructor Create(ARawDisk: TRawDisk; AReadMFTFunc: TReadMFTFunc);
    destructor Destroy; override;
    procedure Reset;
    procedure AssignFromRec(ARec: PGeneralAttr; AOffset: int64);
    procedure ReadBody(ABuf: TBufStream; ABodyOffset: int64); overload;
    function ReadBody(const ABuf; ASize: integer; ABodyOffset: int64): integer; overload;
    function ReadDiskOrMFT(const ABuf; ASize: integer; AFromByte: int64): integer;
    function DecodeClustersList(ABuf: array of byte): boolean;
    function LoadClusters: boolean;
    function GetSTD_INFO: TStdInfoResult;
    function GetFILE_NAME: TFileNameResult;
    function GetATTRIBUTE_LIST: TAttrListArray;
    property AttrType: TAttrType read fType;
    property Name: string read fName;
    property BodySize: integer read fBodySize;
    property BodyStart: int64 read fBodyStart;
    property ContentSize: int64 read fContentSize;
    property AttributeName: string read fName;
    property IsResident: boolean read fIsResident;
    property ClustersList: TDataRuns read GetClustersList;
  end;


implementation

uses Math;


{ TDataRuns }

constructor TDataRuns.Create(AClusterSize: integer);
begin
  inherited Create;
  fClusterSize := AClusterSize;
end;

procedure TDataRuns.AddFragment(AClusterOffset, AClustersCount: int64);
begin
  Assert(AClustersCount >= 0);
  SetLength(fDataRunsAr, Length(fDataRunsAr) + 1);
  with fDataRunsAr[Length(fDataRunsAr)-1] do
  begin
    StartCluster := AClusterOffset;
    ClustersCount := AClustersCount;
  end;
  inc(fClustersCount, AClustersCount);
end;


function TDataRuns.GetCluster(AIndex: longword): TClusterRec;
const
  ERROR_CLUSTER_OUT = 'Cluster Index is out of bound. Index: %d, count: %d';


  function SearchIndex: boolean;
  var
    i: integer;
  begin
    Result := false;
    fArIndexOffset := AIndex;
    for i := 0 to Length(fDataRunsAr) do
    begin
      if fArIndexOffset < fDataRunsAr[i].ClustersCount then
      begin
        fArIndex := i;
        Result := true;
        break;
      end;
      Dec(fArIndexOffset, fDataRunsAr[i].ClustersCount);
    end;
  end;

begin
  Result.StartCluster := NO_VALUE;
  if AIndex >= fClustersCount then
    raise Exception.Create(Format(ERROR_CLUSTER_OUT, [AIndex, fClustersCount]));

  if fCalcIndex <> AIndex then
  begin
    if AIndex > 0 then  // so that there is no overflow during comparison (AIndex - 1 - AIndex - longword)
    begin
      if fCalcIndex <> AIndex - 1 then    // perhaps the index is saved?
      begin
        if not SearchIndex then exit;
      end
      else
        inc(fArIndexOffset)
    end
    else
      begin
        fArIndexOffset := 0;
        fArIndex := 0;
      end;

    if fDataRunsAr[fArIndex].ClustersCount - 1 < fArIndexOffset then    // in column fIndex?
    begin
      inc(fArIndex);
      fArIndexOffset := 0;
    end;
    fCalcIndex := AIndex;
  end;

  Assert(fArIndex < Longword( Length(fDataRunsAr) ));
  with fDataRunsAr[fArIndex] do
  begin
    if ClusterType = ctSparsed then
      Result.StartCluster := 0
    else
      Result.StartCluster := StartCluster + fArIndexOffset;
    Result.ClusterType := ClusterType;
    if fArIndexOffset = ClustersCount - 1 then        // If the last cluster in this fragment.
      Result.LastInCompressBlock := CompressBlockEnd
      // Only applies to compressed attributes. If the attribute is not compressed, this value is always false
    else
      Result.LastInCompressBlock := false;
  end;
end;

function TDataRuns.OffsetToIndex(AFileOffset: int64; var AClusterOffset: integer): longword;
begin
  AClusterOffset := AFileOffset mod fClusterSize;
  Result := (AFileOffset div fClusterSize);
  Assert(Result < fClustersCount);
end;

procedure TDataRuns.Reset;
begin
  fDataRunsAr := nil;
  fClustersCount := 0;
  Assert(fArIndex + fArIndexOffset + fCalcIndex = 0);
end;

{ TAttribute }

constructor TAttribute.Create(ARawDisk: TRawDisk; AReadMFTFunc: TReadMFTFunc);
begin
  inherited Create;
  fLastClusterIndex := NO_VALUE;
  IsMFTOffset := true;
  fRawDisk := ARawDisk;
  Assert(Assigned(AReadMFTFunc));
  fReadMFTFunc := AReadMFTFunc;
end;

destructor TAttribute.Destroy;
begin
  fDataRuns.Free;
  inherited;
end;

function TAttribute.GetSTD_INFO: TStdInfoResult;
var
  vStdInfoRec: TStdInfoAttr;
begin
  Assert( fIsResident and (fType = avStdInfo) );
  ReadDiskOrMFT(vStdInfoRec, SizeOf(TStdInfoAttr), fBodyStart);
  with vStdInfoRec do
  begin
    Result.CreatedDate := FileTimeToLocalDateTime(CreateDate);
    Result.ModifiedDate := FileTimeToLocalDateTime(ModifiedDate);
    Result.LastAccessDate := FileTimeToLocalDateTime(LastAccessDate);
    Result.Attributes := Flags;
  end;
end;

function TAttribute.GetFILE_NAME: TFileNameResult;
var
  vOffset      : int64;
  vFileNameW   : WideString;
  vFileNameRec : TFileNameAttr;
begin
  Assert(fIsResident and (fType = avFileName));
  vOffset := fBodyStart;
  ReadDiskOrMFT(vFileNameRec, SizeOf(TFileNameAttr), vOffset);
  with vFileNameRec do
  begin
    SetLength(vFileNameW, FileNameLength);
    inc(vOffset, SizeOf(TFileNameAttr));
    ReadDiskOrMFT(vFileNameW[1], FileNameLength*2, vOffset);      // UTF-16
    Result.FileName := WideCharToString(PWChar(vFileNameW));
    Result.ParentRecNum := EntryNumToInt(@ParentRec);
    Result.ParentReuseCount := ParentRec.RecReuseCount;
  end;
  Assert(Result.FileName <> '');
end;

function TAttribute.GetATTRIBUTE_LIST: TAttrListArray;
var
  vAttrListElement: TAttrListElement;
  vReadBytes: integer;
  vBodyOffset: integer;
begin
  vReadBytes := 0;
  vBodyOffset := 0;
  repeat
    ReadBody(vAttrListElement, SizeOf(TAttrListElement), vBodyOffset);
    if TAttrType(vAttrListElement.AttributeType) = avData then
    begin
      Assert(vAttrListElement.NameLength = 0);
      SetLength(Result, Length(Result) + 1);
      with Result[Length(Result) - 1] do
      begin
        MFTEntryNum := EntryNumToInt(@vAttrListElement.MFTEntryNum);
        AttrType := TAttrType(vAttrListElement.AttributeType);
      end;
    end;
    inc(vBodyOffset, vAttrListElement.Length);
    inc(vReadBytes, vAttrListElement.Length);
  until vReadBytes >= fContentSize;
end;

function TAttribute.GetClustersList: TDataRuns;
begin
  if fDataRuns = nil then
    LoadClusters;
  Result := fDataRuns;
end;

function TAttribute.LoadClusters: boolean;
var
  vBuf : array of byte;
begin
  SetLength(vBuf, fBodySize);
  ReadDiskOrMFT(vBuf[0], fBodySize, fBodyStart);
  Result := DecodeClustersList(vBuf);
  if fIsCompressed then         // details at the beginning of the unit
    RegroupClustersCompressed;
end;

function TAttribute.DecodeClustersList(ABuf: array of byte): boolean;
var
  vSizesByte     : byte;
  vBufPos        : integer;
  vEndMarker     : longword;
  vCurrentSize   : integer;
  vClusterOffset : int64;
  vClustersCount : int64;
  vClusterOffsetCounter : int64;
begin
  Assert(not fIsResident);
  Result := false;
  vBufPos := 0;
  vEndMarker := 0;
  vClusterOffsetCounter := 0;    // Cluster offset is the sum of offsets of previous clusters
  if fDataRuns = nil then
    fDataRuns := TDataRuns.Create(fRawDisk.ClusterSize);

  repeat                                                     // Find out the size of the next two fields -
    vSizesByte := ABuf[vBufPos];                             // series length and series offset, respectively.
    vClusterOffset := 0;                                     // size of the series length field in bytes
    vClustersCount := 0;

    vCurrentSize := vSizesByte and $0F;
    if vCurrentSize = 0 then exit;                            // series field length
    inc(vBufPos);
    if vBufPos >= Length(ABuf) then exit;
    Move(ABuf[vBufPos], vClustersCount, vCurrentSize);           // series length in clusters

    inc(vBufPos, vCurrentSize);
    if vBufPos >= Length(ABuf) then exit;
    vCurrentSize := vSizesByte shr 4;                            // series start cluster (sign)
    if not fIsCompressed and (vCurrentSize = 0) then exit;       // for compressed files this is acceptable
    Move(ABuf[vBufPos], vClusterOffset, vCurrentSize);
    ConvertToSignValue(vClusterOffset, vCurrentSize);
    inc(vClusterOffsetCounter, vClusterOffset);

    if vClusterOffset <> 0 then                                  // for virtual cluster Offset = 0
      vClusterOffset := vClusterOffsetCounter;
    fDataRuns.AddFragment(vClusterOffset, vClustersCount);
    // In NTFS, the number of clusters after the start cluster includes the start cluster

    inc(vBufPos, vCurrentSize);
    Move(ABuf[vBufPos], vEndMarker, SizeOf(ATTR_END_MARKER));
    Result := true;
  until vEndMarker = ATTR_END_MARKER;
end;

  {$WARNINGS OFF}
procedure TAttribute.RegroupClustersCompressed;
var
  i                 : integer;
  vStartMarkIndex   : integer;
  vCurOffset        : int64;        // offset for current fragment
  vCurCount         : integer;      // number of clusters for current fragment
  vAddedFragClusters: integer;      // number of clusters in fragments from which a 16-cell block is assembled
  vBlockCounter     : integer;      // total cluster counter for splitting into 16-cell blocks
  vBlockInClusters  : integer;      // usually compressed block size = 16 clusters
  vTmp              : integer;
  vClusterType      : TClusterType;
  vSourceArray      : array of TDataRunRec;

  {Nested}
  procedure MarkClustersType(AType: TClusterType);
  var
    i: integer;
  begin
    with fDataRuns do
    begin
      for i := vStartMarkIndex to High(fDataRunsAr) do
        fDataRunsAr[i].ClusterType := AType;

      vStartMarkIndex := High(fDataRunsAr) + 1;
      fDataRunsAr[vStartMarkIndex-1].CompressBlockEnd := true;
    end;
  end;
  {End of Nested}

begin
  Assert( (fDataRuns <> nil) and (fComprsBlockSize > 0) );
  if fComprsBlockSize <= 0 then exit;
  vBlockCounter := 0;
  vStartMarkIndex := 0;
  vAddedFragClusters := 0;
  vBlockInClusters := fComprsBlockSize div fRawDisk.ClusterSize;
  vSourceArray := Pointer(fDataRuns.fDataRunsAr);
  fDataRuns.Reset;

  for i := 0 to High(vSourceArray) do
  begin
    vCurOffset := vSourceArray[i].StartCluster;
    vCurCount := vSourceArray[i].ClustersCount;
    inc(vBlockCounter, vCurCount);
    repeat
      if vBlockCounter >= vBlockInClusters then
        begin
          // to avoid splitting into fragments of 1 block, a fragment that is larger than two blocks.
          // A block without fragments is not compressed or a Sparce block (always without fragments)
          if vAddedFragClusters = 0 then
            begin
              // number of clusters multiple of 16
              vTmp := (vBlockCounter div vBlockInClusters) * vBlockInClusters;
              fDataRuns.AddFragment(vCurOffset, vTmp);
              dec(vBlockCounter, vTmp);
            end
          else
            begin
              // if the current block consists of fragments
              vTmp := vBlockInClusters - vAddedFragClusters;
              if vCurOffset <> 0 then
                fDataRuns.AddFragment(vCurOffset, vTmp);
              dec(vBlockCounter, vBlockInClusters);
            end;
          if vCurOffset <> 0 then
            inc(vCurOffset, vTmp);
          dec(vCurCount, vTmp);
          Assert(vCurCount >= 0);

          // Now the block is assembled and it is known whether the block is compressed or not, -
          // we mark the clusters of the previous fragments included in this block
          if (vCurOffset = 0) and (vAddedFragClusters = 0) then
            vClusterType := ctSparsed
          else
            if vCurOffset = 0 then
              vClusterType := ctCompressed
            else
              vClusterType := ctNormal;
          MarkClustersType(vClusterType);
          vAddedFragClusters := 0;
        end
      else
        begin
          fDataRuns.AddFragment(vCurOffset, vCurCount);
          inc(vAddedFragClusters, vCurCount);
          vCurCount := 0;
        end;
    until vCurCount <= 0;
  end;
end;
  {$WARNINGS ON}

procedure TAttribute.ReadBody(ABuf: TBufStream; ABodyOffset: int64);
var
  vReadBytes: integer;
begin
  if fIsCompressed then
  begin
    Assert(ABuf.Position = 0);
    { This is necessary because to read any cluster of a compressed file, we need to decompress
      first the block, usually a block = 16 clusters. Therefore, it is advisable to read by blocks.}
    if ABuf.Size <> fComprsBlockSize then
      ABuf.Size := fComprsBlockSize;
  end;
  vReadBytes := ReadBody(ABuf.Buffer^, ABuf.RemainSize, ABodyOffset);
  inc(ABuf.Position, vReadBytes);
  Assert(vReadBytes > 0);
end;

function TAttribute.ReadBody(const ABuf; ASize: integer; ABodyOffset: int64): integer;
begin
  Assert(ABodyOffset < fContentSize, IntToStr(ABodyOffset) + ', ' + IntToStr(fContentSize));
  if fIsCompressed and (ASize <> fComprsBlockSize) then
    raise Exception.Create('Read compressed attributes with "ReadBody(ABuf: TBufStream; ABodyOffset: int64)" procedure, this  method does not support it.');

  if fIsResident then
    Result := ReadResident(ABuf, ASize, ABodyOffset)
  else
    begin
      if fDataRuns = nil then
        LoadClusters;

      if fIsCompressed then
        Result := ReadCompressed(ABuf, ASize, ABodyOffset = 0)
      else
        Result := ReadNonResident(ABuf, ASize, ABodyOffset);
    end;
end;

procedure TAttribute.ReadCluster(var ABuf; AIndex: longword);
var
  vDiskSector: int64;
begin
  with fRawDisk do
  begin
    vDiskSector := fDataRuns.Cluster[AIndex].StartCluster * ClusterSize div SectorSize;
    ReadBlockFromSector(ABuf, ClusterSize, vDiskSector);
  end;
end;

function TAttribute.ReadResident(const ABuf; ASize: integer; ABodyOffset: integer): integer;
begin
  if ASize > fContentSize then
    Result := fContentSize
  else
    Result := ASize;
  ReadDiskOrMFT(ABuf, Result, fBodyStart + ABodyOffset);
end;

function TAttribute.ReadNonResident(const ABuf; ASize: integer; ABodyOffset: int64): integer;
var
  vIndex         : longword;
  vClusterOffset : integer;
  vCopySize      : integer;
  vBufPos        : pointer;
begin
  Result := 0;
  vBufPos := @ABuf;
  vIndex := fDataRuns.OffsetToIndex(ABodyOffset, vClusterOffset);
  // The index of the cluster in the array where this offset will start
  repeat
    if fLastClusterIndex <> vIndex then
    begin
      if not Assigned(fClusterBuf) then
        SetLength(fClusterBuf, fRawDisk.ClusterSize);
      ReadCluster(fClusterBuf[0], vIndex);
      fLastClusterIndex := vIndex;
    end;
    vCopySize := (Length(fClusterBuf) - vClusterOffset);
    Assert(vCopySize > 0);
    if ASize < vCopySize then
      vCopySize := ASize;

    Move(fClusterBuf[vClusterOffset], vBufPos^, vCopySize);
    dec(ASize, vCopySize);
    inc(Result, vCopySize);
    vBufPos := Pointer(integer(vBufPos) + vCopySize);
    if Length(fClusterBuf) - vClusterOffset - vCopySize = 0 then // Have read everything?
    begin
      inc(vIndex);                                               // Next cluster
      vClusterOffset := 0;
    end;

    // If the last cluster - destroy the buffer, the file has been read to the end
    if vIndex >= fDataRuns.ClustersCount then
    begin
      fClusterBuf := nil;
      fLastClusterIndex := -1;
    end;
  until (ASize = 0) or (vIndex >= fDataRuns.ClustersCount);
  Assert(Result > 0);
end;

function TAttribute.ReadCompressed(const ABuf; ASize: integer; AFromBegin: boolean): integer;
var
  vBufPos: Pointer;
  vComprBufSize: integer;
begin
  Assert(ASize = fComprsBlockSize);   // read the compressed block at once
  Result := 0;
  vBufPos := @ABuf;
  if AFromBegin then
    fLastClusterIndex := 0
  else
    if fLastClusterIndex >= fDataRuns.ClustersCount then exit;  // if everything was read

  if (fLastClusterIndex > 0) then
  with fDataRuns[fLastClusterIndex-1] do
    if (ClusterType = ctCompressed) and not LastInCompressBlock then
      raise Exception.Create('Invalid Cluster Index: ' + IntToStr(fLastClusterIndex));

  // For a compressed block, you must first copy the clusters to fClusterBuf and decompress them to the output buffer
  if fDataRuns[fLastClusterIndex].ClusterType = ctCompressed then
  begin
    vComprBufSize := fComprsBlockSize - integer(fRawDisk.ClusterSize);
    if Length(fClusterBuf) <> vComprBufSize then
      SetLength(fClusterBuf, vComprBufSize);
    vBufPos := @fClusterBuf[0];
  end;

  while fLastClusterIndex < fDataRuns.ClustersCount do
  begin
    case fDataRuns[fLastClusterIndex].ClusterType of
      ctNormal, ctCompressed:
        begin
          ReadCluster(vBufPos^, fLastClusterIndex);
          vBufPos := Pointer( integer(vBufPos) + integer(fRawDisk.ClusterSize) );
          inc(Result, fRawDisk.ClusterSize);
        end;
      ctSparsed:
        begin
          ZeroMemory(vBufPos, ASize);                                         // Sparses is a block of zeros
          inc(fLastClusterIndex, (ASize div integer(fRawDisk.ClusterSize)) ); // + compressed block size (+16 cl.)
          Result := ASize;
          break;
        end;
    end;
    inc(fLastClusterIndex);
    if (Result = fComprsBlockSize) or                                 // if the block was read, or
       fDataRuns[fLastClusterIndex-1].LastInCompressBlock then break; // cluster marked as last in block
  end;

  if fDataRuns[fLastClusterIndex-1].ClusterType = ctCompressed then
    Result := DecompressLZNT1(fClusterBuf[0], Result, ABuf, ASize);
  if fLastClusterIndex = fDataRuns.ClustersCount then
    fClusterBuf := nil;
end;

function TAttribute.ReadDiskOrMFT(const ABuf; ASize: integer; AFromByte: int64): integer;
begin
  if IsMFTOffset then
    Result := fReadMFTFunc(ABuf, ASize, AFromByte)
  else
  begin
    fRawDisk.ReadBlockCached(ABuf, ASize, AFromByte);
    Result := ASize;
  end;
end;

procedure TAttribute.Reset;
begin
  FreeAndNil(fDataRuns);
  fName := '';
  fLastClusterIndex := NO_VALUE;
end;

procedure TAttribute.AssignFromRec(ARec: PGeneralAttr; AOffset: int64);
const
  RESIDENT_BODY =  (SizeOf(TGeneralAttr) - SizeOf(TGeneralNonResidentAttr)) +
    SizeOf(TGeneralResidentAttr);
var
  vAttrNameW: WideString;
begin
  Reset;
  fType := TAttrType(ARec.AttributeType);
  fIsResident := not ARec.OutsideMFT;
  fIsCompressed := ARec.Flags and ATTR_COMPRESSED = ATTR_COMPRESSED;
  if fIsCompressed then
  begin
    fComprsBlockSize := 1 shl ARec.NonResidentAttr.CompressionBlockSize;  // 2 to the power n
    fComprsBlockSize := fComprsBlockSize * integer(fRawDisk.ClusterSize);
  end;
  if ARec.NameLength > 0 then                 // Attribute name (not file! but ALT stream), UTF 16
  begin
    SetLength(vAttrNameW, ARec.NameLength);
    fReadMFTFunc(vAttrNameW[1], ARec.NameLength*2, AOffset + ARec.NameOffset);
    fName := WideCharToString(PWChar(vAttrNameW));
  end;
  if fIsResident then                         // Resident attribute
    begin
      fBodyStart := AOffset + ARec.ResidentAttr.AttributeOffset;
      fContentSize := ARec.ResidentAttr.Size;
      fBodySize := fContentSize;
    end
  else                                        // Non-resident attribute
    begin
      Assert(ARec.NonResidentAttr.DataRunsOffset < ARec.Length);
      fBodySize := ARec.Length - ARec.NonResidentAttr.DataRunsOffset;
      fBodyStart := AOffset + ARec.NonResidentAttr.DataRunsOffset;
      fContentSize := ARec.NonResidentAttr.RealAttrSize;
    end;
  Assert(fBodySize < 1024, IntToStr(fBodySize));
end;


end.

