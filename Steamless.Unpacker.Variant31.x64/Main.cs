/**
 * Steamless - Copyright (c) 2015 - 2023 atom0s [atom0s@live.com]
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
 * Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
 *
 * By using Steamless, you agree to the above license and its terms.
 *
 *      Attribution - You must give appropriate credit, provide a link to the license and indicate if changes were
 *                    made. You must do so in any reasonable manner, but not in any way that suggests the licensor
 *                    endorses you or your use.
 *
 *   Non-Commercial - You may not use the material (Steamless) for commercial purposes.
 *
 *   No-Derivatives - If you remix, transform, or build upon the material (Steamless), you may not distribute the
 *                    modified material. You are, however, allowed to submit the modified works back to the original
 *                    Steamless project in attempt to have it added to the original project.
 *
 * You may not apply legal terms or technological measures that legally restrict others
 * from doing anything the license permits.
 *
 * No warranties are given.
 */

namespace Steamless.Unpacker.Variant31.x64
{
    using API;
    using API.Crypto;
    using API.Events;
    using API.Extensions;
    using API.Model;
    using API.PE64;
    using API.Services;
    using Classes;
    using System;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Security.Cryptography;

    [SteamlessApiVersion(1, 0)]
    public class Main : SteamlessPlugin
    {
        /// <summary>
        /// Internal logging service instance.
        /// </summary>
        private LoggingService m_LoggingService;

        /// <summary>
        /// Gets the author of this plugin.
        /// </summary>
        public override string Author => "atom0s";

        /// <summary>
        /// Gets the name of this plugin.
        /// </summary>
        public override string Name => "SteamStub Variant 3.1.x Unpacker (x64)";

        /// <summary>
        /// Gets the description of this plugin.
        /// </summary>
        public override string Description => "Unpacker for the 64bit SteamStub variant 3.1.x.";

        /// <summary>
        /// Gets the version of this plugin.
        /// </summary>
        public override Version Version => Assembly.GetExecutingAssembly().GetName().Version;

        /// <summary>
        /// Internal wrapper to log a message.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="type"></param>
        private void Log(string msg, LogMessageType type)
        {
            this.m_LoggingService.OnAddLogMessage(this, new LogMessageEventArgs(msg, type));
        }

        /// <summary>
        /// Initialize function called when this plugin is first loaded.
        /// </summary>
        /// <param name="logService"></param>
        /// <returns></returns>
        public override bool Initialize(LoggingService logService)
        {
            this.m_LoggingService = logService;
            return true;
        }

        /// <summary>
        /// Processing function called when a file is being unpacked. Allows plugins to check the file
        /// and see if it can handle the file for its intended purpose.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public override bool CanProcessFile(string file)
        {
            try
            {
                // Load the file..
                var f = new Pe64File(file);
                if (!f.Parse() || !f.IsFile64Bit() || !f.HasSection(".bind"))
                    return false;

                // Obtain the bind section data..
                var bind = f.GetSectionData(".bind").Take(0x3000).ToArray();

                // Attempt to locate the known v3.x signature..
                var variant = Pe64Helpers.FindPattern(bind, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50");
                if (variant == -1)
                    return false;

                // Attempt to determine the variant version..
                var offset = Pe64Helpers.FindPattern(bind, "48 8D 91 ?? ?? ?? ?? 48"); // 3.0
                if (offset == -1)
                    offset = Pe64Helpers.FindPattern(bind, "48 8D 91 ?? ?? ?? ?? 41"); // 3.1
                if (offset == -1)
                {
                    offset = Pe64Helpers.FindPattern(bind, "48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48"); // 3.1.2
                    if (offset > 0)
                        offset += 5;
                }

                // Ensure a pattern was found..
                if (offset == -1)
                    return false;

                // Read the header size.. (The header size is only 32bit!)
                var headerSize = Math.Abs(BitConverter.ToInt32(bind, (int)offset + 3));

                // Check for the known 3.1 header size..
                return headerSize == 0xF0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Processing function called to allow the plugin to process the file.
        /// </summary>
        /// <param name="file"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public override bool ProcessFile(string file, SteamlessOptions options)
        {
            // Initialize the class members..
            this.TlsAsOep = false;
            this.TlsOepRva = 0;
            this.Options = options;
            this.CodeSectionData = null;
            this.CodeSectionIndex = -1;
            this.XorKey = 0;

            // Parse the file..
            this.File = new Pe64File(file);
            if (!this.File.Parse())
                return false;

            // Announce we are being unpacked with this packer..
            this.Log("该文件包含 SteamStub Variant 3.1 (x64)!", LogMessageType.Information);

            this.Log("步骤 1 - 读取、解码并验证 SteamStub DRM 标头。", LogMessageType.Information);
            if (!this.Step1())
                return false;

            this.Log("步骤 2 - 读取、解码和处理有效内容数据。", LogMessageType.Information);
            if (!this.Step2())
                return false;

            this.Log("步骤 3 - 读取、解码并转存 SteamDRMP.dll 文件。", LogMessageType.Information);
            if (!this.Step3())
                return false;

            this.Log("步骤 4 - 处理 .bind，找到代码部分。", LogMessageType.Information);
            if (!this.Step4())
                return false;

            this.Log("步骤 5 - 读取、解密和处理代码部分。", LogMessageType.Information);
            if (!this.Step5())
                return false;

            this.Log("步骤 6 - 重建并保存解包文件。", LogMessageType.Information);
            if (!this.Step6())
                return false;

            if (this.Options.RecalculateFileChecksum)
            {
                this.Log("步骤 7 - 重建解包文件校验码。", LogMessageType.Information);
                if (!this.Step7())
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Step #1
        /// 
        /// Read, decode and validate the SteamStub DRM header.
        /// </summary>
        /// <returns></returns>
        private bool Step1()
        {
            // Obtain the DRM header data..
            var fileOffset = this.File.GetFileOffsetFromRva(this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint);
            var headerData = new byte[0xF0];
            Array.Copy(this.File.FileData, (long)(fileOffset - 0xF0), headerData, 0, 0xF0);

            // Xor decode the header data..
            this.XorKey = SteamStubHelpers.SteamXor(ref headerData, 0xF0);
            this.StubHeader = Pe64Helpers.GetStructure<SteamStub64Var31Header>(headerData);

            // Validate the header signature..
            if (this.StubHeader.Signature == 0xC0DEC0DF)
                return true;

            // Try again using the Tls callback (if any) as the OEP instead..
            if (this.File.TlsCallbacks.Count == 0)
                return false;

            // Obtain the DRM header data..
            fileOffset = this.File.GetRvaFromVa(this.File.TlsCallbacks[0]);
            fileOffset = this.File.GetFileOffsetFromRva(fileOffset);
            headerData = new byte[0xF0];
            Array.Copy(this.File.FileData, (long)(fileOffset - 0xF0), headerData, 0, 0xF0);

            // Xor decode the header data..
            this.XorKey = SteamStubHelpers.SteamXor(ref headerData, 0xF0);
            this.StubHeader = Pe64Helpers.GetStructure<SteamStub64Var31Header>(headerData);

            // Validate the header signature..
            if (this.StubHeader.Signature != 0xC0DEC0DF)
                return false;

            // Tls was valid for the real oep..
            this.TlsAsOep = true;
            this.TlsOepRva = this.File.GetRvaFromVa(this.File.TlsCallbacks[0]);
            return true;
        }

        /// <summary>
        /// Step #2
        /// 
        /// 读取、解码和处理有效内容数据。
        /// </summary>
        /// <returns></returns>
        private bool Step2()
        {
            // Obtain the payload address and size..
            var payloadAddr = this.File.GetFileOffsetFromRva(this.TlsAsOep ? this.TlsOepRva - this.StubHeader.BindSectionOffset : this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint - this.StubHeader.BindSectionOffset);
            var payloadSize = (this.StubHeader.PayloadSize + 0x0F) & 0xFFFFFFF0;

            // Do nothing if there is no payload..
            if (payloadSize == 0)
                return true;

            this.Log(" --> 文件中包含有效内容数据！", LogMessageType.Debug);

            // Obtain and decode the payload..
            var payload = new byte[payloadSize];
            Array.Copy(this.File.FileData, (long)payloadAddr, payload, 0, payloadSize);
            this.XorKey = SteamStubHelpers.SteamXor(ref payload, payloadSize, this.XorKey);

            try
            {
                if (this.Options.DumpPayloadToDisk)
                {
                    System.IO.File.WriteAllBytes(this.File.FilePath + ".payload", payload);
                    this.Log(" --> 已将有效内容另存！", LogMessageType.Debug);
                }
            }
            catch
            {
                // Do nothing here since it doesn't matter if this fails..
            }

            return true;
        }

        /// <summary>
        /// Step #3
        /// 
        /// 读取、解码并转存 SteamDRMP.dll 文件。
        /// </summary>
        /// <returns></returns>
        private bool Step3()
        {
            // Ensure there is a dll to process..
            if (this.StubHeader.DRMPDllSize == 0)
            {
                this.Log(" --> 文件不包含 SteamDRMP.dll 文件。", LogMessageType.Debug);
                return true;
            }

            this.Log(" --> 文件中包含 SteamDRMP.dll 文件！", LogMessageType.Debug);

            try
            {
                // Obtain the SteamDRMP.dll file address and data..
                var drmpAddr = this.File.GetFileOffsetFromRva(this.TlsAsOep ? this.TlsOepRva - this.StubHeader.BindSectionOffset + this.StubHeader.DRMPDllOffset : this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint - this.StubHeader.BindSectionOffset + this.StubHeader.DRMPDllOffset);
                var drmpData = new byte[this.StubHeader.DRMPDllSize];
                Array.Copy(this.File.FileData, (long)drmpAddr, drmpData, 0, drmpData.Length);

                // Decrypt the data (xtea decryption)..
                SteamStubHelpers.SteamDrmpDecryptPass1(ref drmpData, this.StubHeader.DRMPDllSize, this.StubHeader.EncryptionKeys);

                try
                {
                    if (this.Options.DumpSteamDrmpToDisk)
                    {
                        var basePath = Path.GetDirectoryName(this.File.FilePath) ?? string.Empty;
                        System.IO.File.WriteAllBytes(Path.Combine(basePath, "SteamDRMP.dll"), drmpData);
                        this.Log(" --> 已将 SteamDRMP.dll 另存！", LogMessageType.Debug);
                    }
                }
                catch
                {
                    // Do nothing here since it doesn't matter if this fails..
                }

                return true;
            }
            catch
            {
                this.Log(" --> 尝试解密文件 SteamDRMP.dll 数据时出错！", LogMessageType.Error);
                return false;
            }
        }

        /// <summary>
        /// Step #4
        /// 
        /// Remove the bind section if requested.
        /// Find the code section.
        /// </summary>
        /// <returns></returns>
        private bool Step4()
        {
            // Remove the bind section if its not requested to be saved..
            if (!this.Options.KeepBindSection)
            {
                // Obtain the .bind section..
                var bindSection = this.File.GetSection(".bind");
                if (!bindSection.IsValid)
                    return false;

                // Remove the section..
                this.File.RemoveSection(bindSection);

                // Decrease the header section count..
                var ntHeaders = this.File.NtHeaders;
                ntHeaders.FileHeader.NumberOfSections--;
                this.File.NtHeaders = ntHeaders;

                this.Log(" --> .bind 部分已从文件中删除。", LogMessageType.Debug);
            }
            else
                this.Log(" --> .bind 部分保留在文件中。", LogMessageType.Debug);

            // Skip finding the code section if the file is not encrypted..
            if ((this.StubHeader.Flags & (uint)SteamStubDrmFlags.NoEncryption) == (uint)SteamStubDrmFlags.NoEncryption)
                return true;

            // Find the code section..
            var codeSection = this.File.GetOwnerSection(this.StubHeader.CodeSectionVirtualAddress);

            // Store the code sections index..
            this.CodeSectionIndex = this.File.GetSectionIndex(codeSection);

            return true;
        }

        /// <summary>
        /// Step #5
        /// 
        /// Read, decrypt and process the code section.
        /// </summary>
        /// <returns></returns>
        private bool Step5()
        {
            // Skip decryption if the code section is not encrypted..
            if ((this.StubHeader.Flags & (uint)SteamStubDrmFlags.NoEncryption) == (uint)SteamStubDrmFlags.NoEncryption)
            {
                this.Log(" --> 代码部分未加密。", LogMessageType.Debug);
                return true;
            }

            try
            {
                // Obtain the code section..
                var codeSection = this.File.Sections[this.CodeSectionIndex];
                this.Log($" --> {codeSection.SectionName} 作为主要代码部分链接。", LogMessageType.Debug);
                this.Log($" --> {codeSection.SectionName} 部分已加密。", LogMessageType.Debug);

                if (codeSection.SizeOfRawData == 0)
                {
                    this.Log($" --> {codeSection.SectionName} section is empty; skipping decryption.", LogMessageType.Debug);

                    this.CodeSectionData = new byte[] { };
                    return true;
                }

                // Obtain the code section data..
                var codeSectionData = new byte[codeSection.SizeOfRawData + this.StubHeader.CodeSectionStolenData.Length];
                Array.Copy(this.StubHeader.CodeSectionStolenData, (long)0, codeSectionData, 0, this.StubHeader.CodeSectionStolenData.Length);
                Array.Copy(this.File.FileData, (long)this.File.GetFileOffsetFromRva(codeSection.VirtualAddress), codeSectionData, this.StubHeader.CodeSectionStolenData.Length, codeSection.SizeOfRawData);

                // Create the AES decryption helper..
                var aes = new AesHelper(this.StubHeader.AES_Key, this.StubHeader.AES_IV);
                aes.RebuildIv(this.StubHeader.AES_IV);

                // Decrypt the code section data..
                var data = aes.Decrypt(codeSectionData, CipherMode.CBC, PaddingMode.None);
                if (data == null)
                    return false;

                // Set the code section override data..
                this.CodeSectionData = data;

                return true;
            }
            catch
            {
                this.Log(" --> Error trying to decrypt the files code section data!", LogMessageType.Error);
                return false;
            }
        }

        /// <summary>
        /// Step #6
        /// 
        /// 重建并保存解包文件。
        /// </summary>
        /// <returns></returns>
        private bool Step6()
        {
            FileStream fStream = null;

            try
            {
                // Zero the DosStubData if desired..
                if (this.Options.ZeroDosStubData && this.File.DosStubSize > 0)
                    this.File.DosStubData = Enumerable.Repeat((byte)0, (int)this.File.DosStubSize).ToArray();

                // Rebuild the file sections..
                this.File.RebuildSections(this.Options.DontRealignSections == false);

                // Open the unpacked file for writing..
                var unpackedPath = this.File.FilePath + ".unpacked.exe";
                fStream = new FileStream(unpackedPath, FileMode.Create, FileAccess.ReadWrite);

                // Write the DOS header to the file..
                fStream.WriteBytes(Pe64Helpers.GetStructureBytes(this.File.DosHeader));

                // Write the DOS stub to the file..
                if (this.File.DosStubSize > 0)
                    fStream.WriteBytes(this.File.DosStubData);

                // Update the NT headers..
                var ntHeaders = this.File.NtHeaders;
                ntHeaders.OptionalHeader.AddressOfEntryPoint = (uint)this.StubHeader.OriginalEntryPoint;
                ntHeaders.OptionalHeader.CheckSum = 0;
                this.File.NtHeaders = ntHeaders;

                // Write the NT headers to the file..
                fStream.WriteBytes(Pe64Helpers.GetStructureBytes(ntHeaders));

                // Write the sections to the file..
                for (var x = 0; x < this.File.Sections.Count; x++)
                {
                    var section = this.File.Sections[x];
                    var sectionData = this.File.SectionData[x];

                    // Write the section header to the file..
                    fStream.WriteBytes(Pe64Helpers.GetStructureBytes(section));

                    // Set the file pointer to the sections raw data..
                    var sectionOffset = fStream.Position;
                    fStream.Position = section.PointerToRawData;

                    // Write the sections raw data..
                    var sectionIndex = this.File.Sections.IndexOf(section);
                    if (sectionIndex == this.CodeSectionIndex)
                        fStream.WriteBytes(this.CodeSectionData ?? sectionData);
                    else
                        fStream.WriteBytes(sectionData);

                    // Reset the file offset..
                    fStream.Position = sectionOffset;
                }

                // Set the stream to the end of the file..
                fStream.Position = fStream.Length;

                // Write the overlay data if it exists..
                if (this.File.OverlayData != null)
                    fStream.WriteBytes(this.File.OverlayData);

                this.Log(" --> 解包文件已另存！", LogMessageType.Success);
                this.Log($" --> 文件另存为: {unpackedPath}", LogMessageType.Success);

                return true;
            }
            catch
            {
                this.Log(" --> 另存解包文件时出错！", LogMessageType.Error);
                return false;
            }
            finally
            {
                fStream?.Dispose();
            }
        }

        /// <summary>
        /// Step #7
        /// 
        /// Recalculate the file checksum.
        /// </summary>
        /// <returns></returns>
        private bool Step7()
        {
            var unpackedPath = this.File.FilePath + ".unpacked.exe";
            if (!Pe64Helpers.UpdateFileChecksum(unpackedPath))
            {
                this.Log(" --> 重新计算解包文件校验码时出错！", LogMessageType.Error);
                return false;
            }

            this.Log(" --> 解包文件已更新校验码！", LogMessageType.Success);
            return true;

        }

        /// <summary>
        /// Gets or sets if the Tls callback is being used as the Oep.
        /// </summary>
        private bool TlsAsOep { get; set; }

        /// <summary>
        /// Gets or sets the Tls Oep Rva if it is being used as the Oep.
        /// </summary>
        private ulong TlsOepRva { get; set; }

        /// <summary>
        /// Gets or sets the Steamless options this file was requested to process with.
        /// </summary>
        private SteamlessOptions Options { get; set; }

        /// <summary>
        /// Gets or sets the file being processed.
        /// </summary>
        private Pe64File File { get; set; }

        /// <summary>
        /// Gets or sets the current xor key being used against the file data.
        /// </summary>
        private uint XorKey { get; set; }

        /// <summary>
        /// Gets or sets the DRM stub header.
        /// </summary>
        private SteamStub64Var31Header StubHeader { get; set; }

        /// <summary>
        /// Gets or sets the index of the code section.
        /// </summary>
        private int CodeSectionIndex { get; set; }

        /// <summary>
        /// Gets or sets the decrypted code section data.
        /// </summary>
        private byte[] CodeSectionData { get; set; }
    }
}