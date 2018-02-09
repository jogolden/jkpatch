namespace librpc
{
    public class ProcessList
    {
        public int number;
        public string[] procnames;
        public int[] pids;

        public ProcessList(int number, string[] n, int[] p)
        {
            this.number = number;
            procnames = (string[])n.Clone();
            pids = (int[])p.Clone();
        }

        public int GetPidByName(string procname)
        {
            for (int i = 0; i < number; i++)
            {
                if (procnames[i] == procname)
                {
                    return pids[i];
                }
            }

            return -1;
        }

        public int GetPidContainsName(string procname)
        {
            for (int i = 0; i < number; i++)
            {
                if (procnames[i].Contains(procname))
                {
                    return pids[i];
                }
            }

            return -1;
        }
    }
}
