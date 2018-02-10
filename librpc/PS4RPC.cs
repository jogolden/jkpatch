using System;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace librpc
{
    public class PS4RPC
    {
        private Socket sock = null;
        private IPEndPoint enp = null;
        private bool connected = false;

        private static int RPC_PORT = 733;
        private static uint RPC_PACKET_MAGIC = 0xBDAABBCC;
        private static int RPC_MAX_DATA_LEN = 4096;

        // cmds
        private enum RPC_CMDS : uint
        {
            RPC_PROC_READ = 0xBD000001,
            RPC_PROC_WRITE = 0xBD000002,
            RPC_PROC_LIST = 0xBD000003,
            RPC_PROC_INFO = 0xBD000004,
            RPC_PROC_INTALL = 0xBD000005,
            RPC_PROC_CALL = 0xBD000006,
            RPC_END = 0xBD000007,
            RPC_REBOOT = 0xBD000008,
        };

        // sizes
        private static int RPC_PACKET_SIZE = 12;
        private static int RPC_PROC_READ_SIZE = 16;
        private static int RPC_PROC_WRITE_SIZE = 16;
        private static int RPC_PROC_LIST_SIZE = 36; // this is received
        private static int RPC_PROC_INFO1_SIZE = 4;
        private static int RPC_PROC_INFO2_SIZE = 60; // this is received

        // status
        private static uint RPC_SUCCESS = 0x80000000;
        private static uint RPC_TOO_MUCH_DATA = 0x80000001;
        private static uint RPC_READ_ERROR = 0x80000002;
        private static uint RPC_WRITE_ERROR = 0x80000003;
        private static uint RPC_LIST_ERROR = 0x80000004;
        private static uint RPC_INFO_ERROR = 0x80000005;
        private static uint RPC_INFO_NO_MAP = 0x80000006;
        private static uint RPC_NO_PROC = 0x80000007;

        private static Dictionary<uint, string> StatusMessages = new Dictionary<uint, string>()
        {
            { RPC_SUCCESS, "success"},
            { RPC_TOO_MUCH_DATA, "too much data"},
            { RPC_READ_ERROR, "read error"},
            { RPC_WRITE_ERROR, "write error"},
            { RPC_LIST_ERROR, "process list error"},
            { RPC_INFO_ERROR, "process information error"},
            { RPC_NO_PROC, "no such process error"},
        };

        public static string GetNullTermString(byte[] data, int offset)
        {
            int length = Array.IndexOf<byte>(data, 0, offset) - offset;
            if (length < 0)
            {
                length = data.Length - offset;
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        public PS4RPC(IPAddress addr)
        {
            enp = new IPEndPoint(addr, RPC_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sock.NoDelay = true;
            sock.ReceiveTimeout = sock.SendTimeout = 5 * 1000;
        }

        public PS4RPC(string ip)
        {
            IPAddress addr = null;
            try
            {
                addr = IPAddress.Parse(ip);
            }
            catch (FormatException ex)
            {
                throw ex;
            }

            enp = new IPEndPoint(addr, RPC_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sock.NoDelay = true;
            sock.ReceiveTimeout = sock.SendTimeout = 5 * 1000;
        }

        private void SendCMDPacket(RPC_CMDS cmd, int length)
        {
            MemoryStream stream = new MemoryStream();
            stream.Write(BitConverter.GetBytes(RPC_PACKET_MAGIC), 0, sizeof(uint));
            stream.Write(BitConverter.GetBytes((uint)cmd), 0, sizeof(uint));
            stream.Write(BitConverter.GetBytes(length), 0, sizeof(uint));
            byte[] pack = stream.ToArray();
            sock.Send(pack, RPC_PACKET_SIZE, SocketFlags.None);
        }
        private void SendPacketData(int length, params object[] fields)
        {
            MemoryStream rs = new MemoryStream();
            foreach (object field in fields)
            {
                byte[] bytes = null;

                // todo: clean up and find better way
                if (field.GetType() == typeof(char))
                {
                    bytes = BitConverter.GetBytes((char)field);
                }
                else if (field.GetType() == typeof(byte))
                {
                    bytes = BitConverter.GetBytes((byte)field);
                }
                else if (field.GetType() == typeof(short))
                {
                    bytes = BitConverter.GetBytes((short)field);
                }
                else if (field.GetType() == typeof(ushort))
                {
                    bytes = BitConverter.GetBytes((ushort)field);
                }
                else if (field.GetType() == typeof(int))
                {
                    bytes = BitConverter.GetBytes((int)field);
                }
                else if (field.GetType() == typeof(uint))
                {
                    bytes = BitConverter.GetBytes((uint)field);
                }
                else if (field.GetType() == typeof(long))
                {
                    bytes = BitConverter.GetBytes((long)field);
                }
                else if (field.GetType() == typeof(ulong))
                {
                    bytes = BitConverter.GetBytes((ulong)field);
                }
                else if (field.GetType() == typeof(byte[]))
                {
                    bytes = (byte[])field;
                }

                rs.Write(bytes, 0, bytes.Length);
            }

            byte[] packet = rs.ToArray();

            rs.Dispose();

            sock.Send(packet, length, SocketFlags.None);
        }
        private uint ReceiveRPCStatus()
        {
            byte[] status = new byte[4];
            sock.Receive(status, 4, SocketFlags.None);
            return BitConverter.ToUInt32(status, 0);
        }
        private uint CheckRPCStatus()
        {
            uint status = ReceiveRPCStatus();
            if (status != RPC_SUCCESS && status != RPC_INFO_NO_MAP)
            {
                string value = "";
                StatusMessages.TryGetValue(status, out value);
                throw new Exception("librpc: " + value);
            }

            return status;
        }
        private void SendData(byte[] data, int length)
        {
            // todo: implement looping until success
            if (length != sock.Send(data, length, SocketFlags.None))
            {
                throw new Exception("librpc: could not send data over socket");
            }
        }
        private byte[] ReceiveData(int length)
        {
            MemoryStream s = new MemoryStream();

            int left = length;
            int recv = 0;
            while (left > 0)
            {
                byte[] b = new byte[RPC_MAX_DATA_LEN];
                recv = sock.Receive(b, RPC_MAX_DATA_LEN, SocketFlags.None);
                s.Write(b, 0, recv);
                left -= recv;
            }

            byte[] data = s.ToArray();

            s.Dispose();

            return data;
        }

        public void Connect()
        {
            sock.Connect(enp);
            connected = true;
            SendPacketData(0, 5);
        }
        public void Disconnect()
        {
            SendCMDPacket(RPC_CMDS.RPC_END, 0);
            sock.Dispose();
            connected = false;
        }
        public void Reboot()
        {
            SendCMDPacket(RPC_CMDS.RPC_REBOOT, 0);
            sock.Dispose();
            connected = false;
        }

        public byte[] ReadMemory(int pid, ulong address, int length)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            byte[] data = null;

            if (length > RPC_MAX_DATA_LEN)
            {
                MemoryStream rs = new MemoryStream();

                // read max data length
                SendCMDPacket(RPC_CMDS.RPC_PROC_READ, RPC_PROC_READ_SIZE);
                SendPacketData(RPC_PROC_READ_SIZE, pid, address, RPC_MAX_DATA_LEN);
                CheckRPCStatus();
                rs.Write(ReceiveData(RPC_MAX_DATA_LEN), 0, RPC_MAX_DATA_LEN);

                // call ReadMemory again
                int nextlength = length - RPC_MAX_DATA_LEN;
                byte[] nextdata = ReadMemory(pid, address + (ulong)RPC_MAX_DATA_LEN, nextlength);
                rs.Write(nextdata, 0, nextlength);

                data = rs.ToArray();
                rs.Dispose();
            }
            else
            {
                SendCMDPacket(RPC_CMDS.RPC_PROC_READ, RPC_PROC_READ_SIZE);
                SendPacketData(RPC_PROC_READ_SIZE, pid, address, length);
                CheckRPCStatus();
                data = ReceiveData(length);
            }

            return data;
        }
        public void WriteMemory(int pid, ulong address, byte[] data)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            if (data.Length > RPC_MAX_DATA_LEN)
            {
                // write RPC_MAX_DATA_LEN
                byte[] nowdata = new byte[RPC_MAX_DATA_LEN];
                Array.Copy(data, 0, nowdata, 0, RPC_MAX_DATA_LEN);

                SendCMDPacket(RPC_CMDS.RPC_PROC_WRITE, RPC_PROC_WRITE_SIZE);
                SendPacketData(RPC_PROC_WRITE_SIZE, pid, address, RPC_MAX_DATA_LEN);
                CheckRPCStatus();
                SendData(nowdata, RPC_MAX_DATA_LEN);
                CheckRPCStatus();

                // call WriteMemory again with rest of it
                int nextlength = data.Length - RPC_MAX_DATA_LEN;
                byte[] nextdata = new byte[nextlength];
                Array.Copy(data, RPC_MAX_DATA_LEN, nextdata, 0, nextlength);
                WriteMemory(pid, address + (ulong)RPC_MAX_DATA_LEN, nextdata);
            }
            else
            {
                SendCMDPacket(RPC_CMDS.RPC_PROC_WRITE, RPC_PROC_WRITE_SIZE);
                SendPacketData(RPC_PROC_WRITE_SIZE, pid, address, data.Length);
                CheckRPCStatus();
                SendData(data, data.Length);
                CheckRPCStatus();
            }
        }
        public ProcessList GetProcessList()
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_LIST, 0);

            CheckRPCStatus();

            // recv count
            byte[] bnumber = new byte[4];
            sock.Receive(bnumber, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(bnumber, 0);

            // recv data
            byte[] data = ReceiveData(number * RPC_PROC_LIST_SIZE);

            // parse data
            string[] procnames = new string[number];
            int[] pids = new int[number];
            for (int i = 0; i < number; i++)
            {
                int offset = i * RPC_PROC_LIST_SIZE;
                procnames[i] = GetNullTermString(data, offset);
                pids[i] = BitConverter.ToInt32(data, offset + 32);
            }

            return new ProcessList(number, procnames, pids);
        }
        public ProcessInfo GetProcessInfo(int pid)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_INFO, RPC_PROC_INFO1_SIZE);
            SendPacketData(RPC_PROC_INFO1_SIZE, pid);

            uint status = CheckRPCStatus();
            if (status == RPC_INFO_NO_MAP)
            {
                return new ProcessInfo(pid, null);
            }

            // recv count
            byte[] bnumber = new byte[4];
            sock.Receive(bnumber, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(bnumber, 0);

            // recv data
            byte[] data = ReceiveData(number * RPC_PROC_INFO2_SIZE);

            // parse data
            ProcessInfo.VirtualMemoryEntry[] entries = new ProcessInfo.VirtualMemoryEntry[number];
            for (int i = 0; i < number; i++)
            {
                int offset = i * RPC_PROC_INFO2_SIZE;
                entries[i] = new ProcessInfo.VirtualMemoryEntry();

                entries[i].name = GetNullTermString(data, offset);
                entries[i].start = BitConverter.ToUInt64(data, offset + 32);
                entries[i].end = BitConverter.ToUInt64(data, offset + 40);
                entries[i].offset = BitConverter.ToUInt64(data, offset + 48);
                entries[i].prot = BitConverter.ToUInt32(data, offset + 56);
            }

            return new ProcessInfo(pid, entries);
        }

        // read wrappers
        public Byte ReadByte(int pid, ulong address)
        {
            return ReadMemory(pid, address, sizeof(Byte))[0];
        }
        public Char ReadChar(int pid, ulong address)
        {
            return BitConverter.ToChar(ReadMemory(pid, address, sizeof(Char)), 0);
        }
        public Int16 ReadInt16(int pid, ulong address)
        {
            return BitConverter.ToInt16(ReadMemory(pid, address, sizeof(Int16)), 0);
        }
        public UInt16 ReadUInt16(int pid, ulong address)
        {
            return BitConverter.ToUInt16(ReadMemory(pid, address, sizeof(UInt16)), 0);
        }
        public Int32 ReadInt32(int pid, ulong address)
        {
            return BitConverter.ToInt32(ReadMemory(pid, address, sizeof(Int32)), 0);
        }
        public UInt32 ReadUInt32(int pid, ulong address)
        {
            return BitConverter.ToUInt32(ReadMemory(pid, address, sizeof(UInt32)), 0);
        }
        public Int64 ReadInt64(int pid, ulong address)
        {
            return BitConverter.ToInt64(ReadMemory(pid, address, sizeof(Int64)), 0);
        }
        public UInt64 ReadUInt64(int pid, ulong address)
        {
            return BitConverter.ToUInt64(ReadMemory(pid, address, sizeof(UInt64)), 0);
        }

        // write wrappers
        public void WriteByte(int pid, ulong address, Byte value)
        {
            WriteMemory(pid, address, new byte[] { value });
        }
        public void WriteChar(int pid, ulong address, Char value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt16(int pid, ulong address, Int16 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt16(int pid, ulong address, UInt16 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt32(int pid, ulong address, Int32 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt32(int pid, ulong address, UInt32 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt64(int pid, ulong address, Int64 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt64(int pid, ulong address, UInt64 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
    }
}
