(*
Alexander Shyshko, 2009 - 2010, alitrun@gmail.com

Main source:
Brian Carria - Forensic Analysis of File Systems (book)

  TNTFSDrive
  -----------

  IsClustersFree(AFile: TMFTEntry): boolean;
  Checking all clusters where the file is located. If they are all free - only then the file can be restored.


*)

unit ntfsDrive;

interface

uses
  Windows, BaseIOClasses, ntfsMFT, ntfsAttributes, ntfsStructures;


type
  TClusterStatus = (csFree, csAllocated, csOutOfBound);
  TClustersBitmap = class(TMFTEntry)
  private
    fRawDisk: TRawDisk;
    fBitmapBuf: TBufStream;
    fFileOffset: int64;
  public
    constructor Create(ARawDisk: TRawDisk);
    destructor Destroy; override;
    function GetClusterStatus(ACluster: int64): TClusterStatus;
  end;


  TNTFSDrive = class(TFileSystemDrive)
  private
    fMFT: TMFTFile;
    fClustersBitmap: TClustersBitmap;
    fBootSectorRec: TBootSectorRec;
    procedure DoScanProgress(AMFTNum: int64);
    function IsClustersFree(Attribute: TAttribute): boolean;
  protected
    function IsStreamClustersFree(AFile: TBaseFile; AStreamNum: integer): boolean; override;
  public
    constructor Create(ADisk: char);
    destructor Destroy; override;
    procedure StartSearch(AStopPtr: PBOOL); override;
  end;


implementation

const
  NO_VALUE = -1;
  BITMAP_CACHE_SIZE = 4096;



{ TNTFSDrive }

constructor TNTFSDrive.Create(ADisk: char);
begin
  inherited;
  fRawDisk.CacheSize := RAW_DISK_CACHE_SIZE;
  fRawDisk.ReadBlockFromSector(fBootSectorRec, SizeOf(TBootSectorRec), 0);
  fMFT := TMFTFile.Create(fRawDisk, PBootSectorRec(@fBootSectorRec));

  fClustersBitmap := TClustersBitmap.Create(fRawDisk);          // Load the cluster map
  fMFT.LoadEntry(METAFILE_BITMAP, fClustersBitmap);
end;

destructor TNTFSDrive.Destroy;
begin
  fMFT.Free;
  fClustersBitmap.Free;
  inherited;
end;

function TNTFSDrive.IsClustersFree(Attribute: TAttribute): boolean;
var
  i: longword;
  vCluster: TClusterRec;
begin
  with Attribute.ClustersList do
  begin
    Result := ClustersCount > 0;                              // default value
    for i := 0 to ClustersCount - 1 do
    begin
      vCluster := Cluster[i];
      if vCluster.ClusterType <> ctSparsed then
        if fClustersBitmap.GetClusterStatus(vCluster.StartCluster) <> csFree then
        begin
          Result := false;
          break;
        end;
    end;
  end;
end;

procedure TNTFSDrive.StartSearch(AStopPtr: PBOOL);
var
  i: integer;
  vIsDir: boolean;
  vAccepted: boolean;
  vEntry: TMFTEntry;
begin
  Assert( Assigned(fOnFileCheck) );
  inherited;
  fRawDisk.OpenReadOnly;
  // the disk can be opened because the MFT has been initialized. The disk is also automatically opened when calling the disk read functions.

  vEntry := nil;
  // But when REscanning, this call is necessary because it is necessary to initialize
  // ClusterSize and SectorSize (they are accessed before calling the read function).

  try
    for i := fMFT.StartUserRecordNum to fMFT.RecordsCount - 1 do
    begin
      if fStop^ then exit;
      if Assigned(fOnEntryScan) then
        fOnEntryScan;

      if (fMFT.GetEntryStatus(i, vIsDir) = esDeleted) and not vIsDir then
      begin
        if vEntry = nil then
          vEntry := TMFTEntry.Create
        else
          vEntry.Reset;

        if fMFT.LoadEntry(i, vEntry) then
        begin
          fOnFileCheck(vEntry, vAccepted);
          if vAccepted then
          begin
            if not vEntry.DataAttr[0].IsResident then      // file contents (base attribute $DATA)
              if not IsClustersFree(vEntry.DataAttr[0]) then Continue;
            fFilesList.Add(vEntry);
            if Assigned(fAfterFileAdded) then
              fAfterFileAdded;
            vEntry := nil;
          end;
        end;
      end;
      DoScanProgress(i);
    end;
  finally
    vEntry.Free;
    fRawDisk.Close;                                  // maybe the last entry was not accepted
  end;
end;

procedure TNTFSDrive.DoScanProgress(AMFTNum: int64);
begin
  inherited DoScanProgress((AMFTNum + 1) * 100 div fMFT.RecordsCount);
end;

function TNTFSDrive.IsStreamClustersFree(AFile: TBaseFile; AStreamNum: integer): boolean;
begin
  Result := true;
  with TMFTEntry(AFile) do
    if not DataAttr[AStreamNum + 1].IsResident then
      Result := IsClustersFree( DataAttr[AStreamNum + 1] );
end;


{ TClustersBitmap }

constructor TClustersBitmap.Create(ARawDisk: TRawDisk);
begin
  inherited Create;
  fRawDisk := ARawDisk;
  fFileOffset := NO_VALUE;
  fBitmapBuf := TBufStream.Create(BITMAP_CACHE_SIZE);
end;

destructor TClustersBitmap.Destroy;
begin
  fBitmapBuf.Free;
  inherited;
end;

function TClustersBitmap.GetClusterStatus(ACluster: int64): TClusterStatus;
var
  vNeedByte : longword;
  vBitOffset: integer;
  vWorkByte : byte;
begin
  Result := csOutOfBound;
  vNeedByte := ACluster div 8;
  if vNeedByte >= DataAttr[0].ContentSize then exit;
  // Bit is in byte at offset vNeedByte. Offset outside file boundaries


  if (fFileOffset = NO_VALUE) or
     (vNeedByte < fFileOffset) or (vNeedByte >= fFileOffset + fBitmapBuf.Size) then
  begin
    fBitmapBuf.Position := 0;
    DataAttr[0].ReadBody(fBitmapBuf, vNeedByte);
    fFileOffset := vNeedByte;
  end;
  fBitmapBuf.Position := vNeedByte - fFileOffset;
  Move(fBitmapBuf.Buffer^, vWorkByte, SizeOf(vWorkByte));
  vBitOffset := ACluster mod 8;
  vWorkByte  := (vWorkByte shr vBitOffset) and $01;         // Leave only the least significant bit
  if vWorkByte = 0 then
    Result := csFree
  else
    Result := csAllocated;
end;

end.


