namespace KenSoftware.Security
{
    public static class FileSecurity
    {
        public static bool IsExecutable(byte[] fileBytes)
        {
            if (fileBytes == null || fileBytes.Length < 4)
                return false;

            // Windows EXE/DLL (MZ)
            if (fileBytes[0] == 0x4D && fileBytes[1] == 0x5A)
                return true;

            // ELF (Linux)
            if (fileBytes[0] == 0x7F &&
                fileBytes[1] == 0x45 &&
                fileBytes[2] == 0x4C &&
                fileBytes[3] == 0x46)
                return true;

            // Mach-O (macOS)
            if (
                (fileBytes[0] == 0xFE && fileBytes[1] == 0xED &&
                 fileBytes[2] == 0xFA && fileBytes[3] == 0xCE) ||
                (fileBytes[0] == 0xFE && fileBytes[1] == 0xED &&
                 fileBytes[2] == 0xFA && fileBytes[3] == 0xCF) ||
                (fileBytes[0] == 0xCF && fileBytes[1] == 0xFA &&
                 fileBytes[2] == 0xED && fileBytes[3] == 0xFE)
            )
                return true;

            return false;
        }

        public static bool IsExecutable(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[4];
            stream.Read(buffer);
            stream.Position = 0;

            return IsExecutable(buffer.ToArray());
        }
    }
}
