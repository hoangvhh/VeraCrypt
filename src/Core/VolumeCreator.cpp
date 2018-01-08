/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/
#include <stdio.h>
#include "Volume/EncryptionTest.h"
#include "Volume/EncryptionModeXTS.h"
#include "Core.h"

#ifdef TC_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "VolumeCreator.h"
#include "FatFormatter.h"

namespace VeraCrypt
{
	VolumeCreator::VolumeCreator ()
		: SizeDone (0)
	{
	}

	VolumeCreator::~VolumeCreator ()
	{
	}

	void VolumeCreator::Abort ()
	{
		AbortRequested = true;
	}

	void VolumeCreator::CheckResult ()
	{
		if (ThreadException)
			ThreadException->Throw();
	}

	void VolumeCreator::CreationThread ()
	{
		try
		{
			uint64 endOffset;
			uint64 filesystemSize = Layout->GetDataSize (HostSize);

			if (filesystemSize < 1)
				throw ParameterIncorrect (SRC_POS);

			DataStart = Layout->GetDataOffset (HostSize);
			WriteOffset = DataStart;
			endOffset = DataStart + Layout->GetDataSize (HostSize);

			fprintf(stdout, "========== %d DataStart %ld \n", __LINE__, DataStart);
			fprintf(stdout, "========== %d endOffset %ld \n", __LINE__, endOffset);

			VolumeFile->SeekAt (DataStart);

			// Create filesystem
			if (Options->Filesystem == VolumeCreationOptions::FilesystemType::FAT)
			{
				if (filesystemSize < TC_MIN_FAT_FS_SIZE || filesystemSize > TC_MAX_FAT_SECTOR_COUNT * Options->SectorSize)
					throw ParameterIncorrect (SRC_POS);

				struct WriteSectorCallback : public FatFormatter::WriteSectorCallback
				{
					WriteSectorCallback (VolumeCreator *creator) : Creator (creator), OutputBuffer (File::GetOptimalWriteSize()), OutputBufferWritePos (0) { }

					virtual bool operator() (const BufferPtr &sector)
					{
						OutputBuffer.GetRange (OutputBufferWritePos, sector.Size()).CopyFrom (sector);
						OutputBufferWritePos += sector.Size();

						if (OutputBufferWritePos >= OutputBuffer.Size())
							FlushOutputBuffer();

						return !Creator->AbortRequested;
					}

					void FlushOutputBuffer ()
					{
						if (OutputBufferWritePos > 0)
						{
							Creator->Options->EA->EncryptSectors (OutputBuffer.GetRange (0, OutputBufferWritePos),
								Creator->WriteOffset / ENCRYPTION_DATA_UNIT_SIZE, OutputBufferWritePos / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);

							Creator->VolumeFile->Write (OutputBuffer.GetRange (0, OutputBufferWritePos));

							fprintf(stdout, "========== %d write OutputBufferWritePos \n", __LINE__);

							Creator->WriteOffset += OutputBufferWritePos;
							Creator->SizeDone.Set (Creator->WriteOffset - Creator->DataStart);

							OutputBufferWritePos = 0;
						}
					}

					VolumeCreator *Creator;
					SecureBuffer OutputBuffer;
					size_t OutputBufferWritePos;
				};

				WriteSectorCallback sectorWriter (this);
				FatFormatter::Format (sectorWriter, filesystemSize, Options->FilesystemClusterSize, Options->SectorSize);
				sectorWriter.FlushOutputBuffer();
			}

			if (!Options->Quick)
			{
				// Empty sectors are encrypted with different key to randomize plaintext
				Core->RandomizeEncryptionAlgorithmKey (Options->EA);

				SecureBuffer outputBuffer (File::GetOptimalWriteSize());
				uint64 dataFragmentLength = outputBuffer.Size();

				while (!AbortRequested && WriteOffset < endOffset)
				{
					if (WriteOffset + dataFragmentLength > endOffset)
						dataFragmentLength = endOffset - WriteOffset;

					outputBuffer.Zero();
					uint64 current = VolumeFile->Current();
					uint64 readLen;

					if (current == 0x3020000) {
						fprintf(stdout, "----- readLen %ld - current %ld - %x\n", readLen, current, current);
					}

					VolumeFile->SeekAt(current);
					readLen = VolumeFile->Read(outputBuffer);
					VolumeFile->SeekAt(current);
					// fprintf(stdout, "----- readLen %ld - current %ld - %x\n", readLen, current, current);

					// Options->EA->EncryptSectors (outputBuffer, WriteOffset / ENCRYPTION_DATA_UNIT_SIZE, dataFragmentLength / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);
					VolumeFile->Write (outputBuffer, (size_t) dataFragmentLength);

					// if (current == 0x3020000) {
					// 	SecureBuffer buff (File::GetOptimalWriteSize());
					// 	for (int i = 0; i < 0x500; i++) {
					// 		fprintf(stdout, "0x%x ", buff.Ptr()[i]);
					// 		if (i%20==19)
					// 			fprintf(stdout, "\n");
					// 	}
					// }

					WriteOffset += dataFragmentLength;
					SizeDone.Set (WriteOffset - DataStart);
				}
			}

			if (!AbortRequested)
			{
				SizeDone.Set (Options->Size);

				// Backup header
				SecureBuffer backupHeader (Layout->GetHeaderSize());

				SecureBuffer backupHeaderSalt (VolumeHeader::GetSaltSize());
				RandomNumberGenerator::GetData (backupHeaderSalt);

				Options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, Options->Pim, backupHeaderSalt);

				Layout->GetHeader()->EncryptNew (backupHeader, backupHeaderSalt, HeaderKey, Options->VolumeHeaderKdf);

				if (Options->Quick || Options->Type == VolumeType::Hidden)
					VolumeFile->SeekEnd (Layout->GetBackupHeaderOffset());

				uint64 current = VolumeFile->Current();

				VolumeFile->Write (backupHeader);

				fprintf(stdout, "========== %d write backupHeader: pos %d - %ld\n", __LINE__, current, backupHeader.Size());

				if (Options->Type == VolumeType::Normal)
				{
					// Write fake random header to space reserved for hidden volume header
					VolumeLayoutV2Hidden hiddenLayout;
					shared_ptr <VolumeHeader> hiddenHeader (hiddenLayout.GetHeader());
					SecureBuffer hiddenHeaderBuffer (hiddenLayout.GetHeaderSize());

					VolumeHeaderCreationOptions headerOptions;
					headerOptions.EA = Options->EA;
					headerOptions.Kdf = Options->VolumeHeaderKdf;
					headerOptions.Type = VolumeType::Hidden;

					headerOptions.SectorSize = Options->SectorSize;

					headerOptions.VolumeDataStart = HostSize - hiddenLayout.GetHeaderSize() * 2 - Options->Size;
					headerOptions.VolumeDataSize = hiddenLayout.GetMaxDataSize (Options->Size);

					// Master data key
					SecureBuffer hiddenMasterKey(Options->EA->GetKeySize() * 2);
					RandomNumberGenerator::GetData (hiddenMasterKey);
					headerOptions.DataKey = hiddenMasterKey;

					// PKCS5 salt
					SecureBuffer hiddenSalt (VolumeHeader::GetSaltSize());
					RandomNumberGenerator::GetData (hiddenSalt);
					headerOptions.Salt = hiddenSalt;

					// Header key
					SecureBuffer hiddenHeaderKey (VolumeHeader::GetLargestSerializedKeySize());
					RandomNumberGenerator::GetData (hiddenHeaderKey);
					headerOptions.HeaderKey = hiddenHeaderKey;

					hiddenHeader->Create (backupHeader, headerOptions);

					current = VolumeFile->Current();

					VolumeFile->Write (backupHeader);

					fprintf(stdout, "========== %d write backupHeader: pos %d - %ld\n", __LINE__, current, backupHeader.Size());
				}

				VolumeFile->Flush();
			}
		}
		catch (Exception &e)
		{
			ThreadException.reset (e.CloneNew());
		}
		catch (exception &e)
		{
			ThreadException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
		}
		catch (...)
		{
			ThreadException.reset (new UnknownException (SRC_POS));
		}

		SecureBuffer buff (File::GetOptimalWriteSize());
		VolumeFile->SeekAt(0x3020000);
		VolumeFile->Read(buff);
		for (int i = 0; i < 0x500; i++) {
			fprintf(stdout, "0x%x ", buff.Ptr()[i]);
			if (i%20==19)
				fprintf(stdout, "\n");
		}

		VolumeFile->Close();
		VolumeFile.reset();
		mProgressInfo.CreationInProgress = false;
	}

	void VolumeCreator::CreateVolume (shared_ptr <VolumeCreationOptions> options)
	{
		EncryptionTest::TestAll();

		{
#ifdef TC_UNIX
			// Temporarily take ownership of a device if the user is not an administrator
			UserId origDeviceOwner ((uid_t) -1);

			if (!Core->HasAdminPrivileges() && options->Path.IsDevice())
			{
				origDeviceOwner = FilesystemPath (wstring (options->Path)).GetOwner();
				Core->SetFileOwner (options->Path, UserId (getuid()));
			}

			finally_do_arg2 (FilesystemPath, options->Path, UserId, origDeviceOwner,
			{
				if (finally_arg2.SystemId != (uid_t) -1)
					Core->SetFileOwner (finally_arg, finally_arg2);
			});
#endif

			VolumeFile.reset (new File);
			VolumeFile->Open (options->Path,
				(options->Path.IsDevice() || options->Type == VolumeType::Hidden) ? File::OpenReadWrite : File::CreateReadWrite,
				File::ShareNone);

			HostSize = VolumeFile->Length();
		}

		/*/test
		fprintf(stdout, "start! \n\n");
		uint64 writeOffset, readOffset, copySize, removeSize;
		uint64 sector_size, filesystemSize, endOffset;

		// (gdb) p DataStart
		// $1 = 131072
		// (gdb) p endOffset
		// $2 = 107872256
		// (gdb) p filesystemSize
		// $3 = 107741184


		// filesystemSize = Layout->GetDataSize (HostSize);
		// endOffset = Layout->GetDataOffset (HostSize) + Layout->GetDataSize (HostSize);

		// sector_size = VolumeFile->GetDeviceSectorSize();

		filesystemSize = 107741184;
		endOffset = 107872256;

		sector_size = VolumeFile->GetDeviceSectorSize();

		removeSize = 64 * 1024 * 2;
		writeOffset = endOffset - sector_size;
		readOffset = endOffset - sector_size - removeSize;

		SecureBuffer buff (sector_size);
		copySize = sector_size;

		while (readOffset >= 0) {
			VolumeFile->SeekAt(readOffset);
			VolumeFile->Read(buff);

			VolumeFile->SeekAt(writeOffset);
			VolumeFile->Write(buff, copySize);

			if (readOffset == 0)
				break;

			if (readOffset < sector_size)
				copySize = readOffset;
			readOffset -= copySize;
			writeOffset -= copySize;
		}
		fprintf(stdout, "done! \n\n");
		// VolumeFile.reset();
		// mProgressInfo.CreationInProgress = false;
		// return;
		fprintf(stdout, "done! \n\n");
		VolumeFile->SeekAt(0);
		//*/

		try
		{
			// Sector size
			if (options->Path.IsDevice())
			{
				options->SectorSize = VolumeFile->GetDeviceSectorSize();

				if (options->SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
					|| options->SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
#if !defined (TC_LINUX) && !defined (TC_MACOSX)
					|| options->SectorSize != TC_SECTOR_SIZE_LEGACY
#endif
					|| options->SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
				{
					throw UnsupportedSectorSize (SRC_POS);
				}
			}
			else
				options->SectorSize = TC_SECTOR_SIZE_FILE_HOSTED_VOLUME;

			// Volume layout
			switch (options->Type)
			{
			case VolumeType::Normal:
				Layout.reset (new VolumeLayoutV2Normal());
				break;

			case VolumeType::Hidden:
				Layout.reset (new VolumeLayoutV2Hidden());

				if (HostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE)
					throw ParameterIncorrect (SRC_POS);
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			// Volume header
			shared_ptr <VolumeHeader> header (Layout->GetHeader());
			SecureBuffer headerBuffer (Layout->GetHeaderSize());

			VolumeHeaderCreationOptions headerOptions;
			headerOptions.EA = options->EA;
			headerOptions.Kdf = options->VolumeHeaderKdf;
			headerOptions.Type = options->Type;

			headerOptions.SectorSize = options->SectorSize;

			if (options->Type == VolumeType::Hidden)
				headerOptions.VolumeDataStart = HostSize - Layout->GetHeaderSize() * 2 - options->Size;
			else
				headerOptions.VolumeDataStart = Layout->GetHeaderSize() * 2;

			headerOptions.VolumeDataSize = Layout->GetMaxDataSize (options->Size);

			if (headerOptions.VolumeDataSize < 1)
				throw ParameterIncorrect (SRC_POS);

			// Master data key
			MasterKey.Allocate (options->EA->GetKeySize() * 2);
			RandomNumberGenerator::GetData (MasterKey);
			headerOptions.DataKey = MasterKey;

			// PKCS5 salt
			SecureBuffer salt (VolumeHeader::GetSaltSize());
			RandomNumberGenerator::GetData (salt);
			headerOptions.Salt = salt;

			// Header key
			HeaderKey.Allocate (VolumeHeader::GetLargestSerializedKeySize());
			PasswordKey = Keyfile::ApplyListToPassword (options->Keyfiles, options->Password);
			options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, options->Pim, salt);
			headerOptions.HeaderKey = HeaderKey;

			header->Create (headerBuffer, headerOptions);

			// Write new header
			if (Layout->GetHeaderOffset() >= 0)
				VolumeFile->SeekAt (Layout->GetHeaderOffset());
			else
				VolumeFile->SeekEnd (Layout->GetHeaderOffset());

			uint64 current = VolumeFile->Current();

			VolumeFile->Write (headerBuffer);

			fprintf(stdout, "========== %d write headerBuffer: pos %ld - %ld\n", __LINE__, current, headerBuffer.Size());

			if (options->Type == VolumeType::Normal)
			{
				// Write fake random header to space reserved for hidden volume header
				VolumeLayoutV2Hidden hiddenLayout;
				shared_ptr <VolumeHeader> hiddenHeader (hiddenLayout.GetHeader());
				SecureBuffer hiddenHeaderBuffer (hiddenLayout.GetHeaderSize());

				headerOptions.Type = VolumeType::Hidden;

				headerOptions.VolumeDataStart = HostSize - hiddenLayout.GetHeaderSize() * 2 - options->Size;
				headerOptions.VolumeDataSize = hiddenLayout.GetMaxDataSize (options->Size);

				// Master data key
				SecureBuffer hiddenMasterKey(options->EA->GetKeySize() * 2);
				RandomNumberGenerator::GetData (hiddenMasterKey);
				headerOptions.DataKey = hiddenMasterKey;

				// PKCS5 salt
				SecureBuffer hiddenSalt (VolumeHeader::GetSaltSize());
				RandomNumberGenerator::GetData (hiddenSalt);
				headerOptions.Salt = hiddenSalt;

				// Header key
				SecureBuffer hiddenHeaderKey (VolumeHeader::GetLargestSerializedKeySize());
				RandomNumberGenerator::GetData (hiddenHeaderKey);
				headerOptions.HeaderKey = hiddenHeaderKey;

				hiddenHeader->Create (headerBuffer, headerOptions);

				current = VolumeFile->Current();

				VolumeFile->Write (headerBuffer);

				fprintf(stdout, "========== %d write headerBuffer: pos %ld - %ld\n", __LINE__, current, headerBuffer.Size());
			}

			// Data area keys
			options->EA->SetKey (MasterKey.GetRange (0, options->EA->GetKeySize()));
			shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
			mode->SetKey (MasterKey.GetRange (options->EA->GetKeySize(), options->EA->GetKeySize()));
			options->EA->SetMode (mode);

			Options = options;
			AbortRequested = false;

			mProgressInfo.CreationInProgress = true;

			struct ThreadFunctor : public Functor
			{
				ThreadFunctor (VolumeCreator *creator) : Creator (creator) { }
				virtual void operator() ()
				{
					Creator->CreationThread ();
				}
				VolumeCreator *Creator;
			};

			Thread thread;
			thread.Start (new ThreadFunctor (this));
		}
		catch (...)
		{
			VolumeFile.reset();
			throw;
		}

		fprintf(stdout, "========== %s:  %d\n", __FUNCTION__, __LINE__);
	}

	VolumeCreator::KeyInfo VolumeCreator::GetKeyInfo () const
	{
		KeyInfo info;
		info.HeaderKey = HeaderKey;
		info.MasterKey = MasterKey;
		return info;
	}

	VolumeCreator::ProgressInfo VolumeCreator::GetProgressInfo ()
	{
		mProgressInfo.SizeDone = SizeDone.Get();
		return mProgressInfo;
	}
}
