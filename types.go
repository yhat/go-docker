package docker

import "time"

type ChangeType int

const (
	ChangeModify = iota
	ChangeAdd
	ChangeDelete
)

type ContainerConfig struct {
	Hostname        string
	Domainname      string
	User            string
	Memory          int64
	MemorySwap      int64
	CpuShares       int64
	Cpuset          string
	AttachStdin     bool
	AttachStdout    bool
	AttachStderr    bool
	PortSpecs       []string
	ExposedPorts    map[string]struct{}
	Tty             bool
	OpenStdin       bool
	StdinOnce       bool
	Env             []string
	Cmd             []string
	Image           string
	Volumes         map[string]struct{}
	WorkingDir      string
	Entrypoint      []string
	NetworkDisabled bool
	OnBuild         []string

	// This is used only by the create command
	HostConfig HostConfig
}

type HostConfig struct {
	Binds           []string
	ContainerIDFile string
	LxcConf         []map[string]string
	Privileged      bool
	PortBindings    map[string][]PortBinding
	Links           []string
	PublishAllPorts bool
	Dns             []string
	DnsSearch       []string
	VolumesFrom     []string
	NetworkMode     string
	RestartPolicy   RestartPolicy
	Memory          int64
	MemorySwap      int64
	CpuShares       int64
	CpuPeriod       int64
	CpusetCpus      string
	CpusetMems      string
}

type ExecConfig struct {
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	Cmd          []string
	Container    string
	Detach       bool
}

type LogOptions struct {
	Follow     bool
	Stdout     bool
	Stderr     bool
	Timestamps bool
	Tail       int64
}

type RestartPolicy struct {
	Name              string
	MaximumRetryCount int64
}

type PortBinding struct {
	HostIp   string
	HostPort string
}

type ContainerInfo struct {
	Id      string
	Created string
	Path    string
	Name    string
	Args    []string
	ExecIDs []string
	Config  *ContainerConfig
	State   struct {
		Running    bool
		Paused     bool
		Restarting bool
		Pid        int
		ExitCode   int
		StartedAt  time.Time
		FinishedAt time.Time
		Ghost      bool
	}
	Image           string
	NetworkSettings struct {
		IpAddress   string
		IpPrefixLen int
		Gateway     string
		Bridge      string
		Ports       map[string][]PortBinding
	}
	SysInitPath    string
	ResolvConfPath string
	Volumes        map[string]string
	HostConfig     *HostConfig
}

type Port struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

type Container struct {
	Id         string
	Names      []string
	Image      string
	Command    string
	Created    int64
	Status     string
	Ports      []Port
	SizeRw     int64
	SizeRootFs int64
}

type Event struct {
	Id     string
	Status string
	From   string
	Time   int64
}

type Version struct {
	Version   string
	GitCommit string
	GoVersion string
}

type RespContainersCreate struct {
	Id       string
	Warnings []string
}

type Image struct {
	Created     int64
	Id          string
	ParentId    string
	RepoTags    []string
	Size        int64
	VirtualSize int64
}

//returned by History
type ImageLayer struct {
	Id        string
	Created   int64
	CreatedBy string
	Comment   string
	Size      int64
	Tags      []string
}

// returned by InspectImage
type ImageInfo struct {
	Created   string
	Container string
	Id        string
	Parent    string
	Size      int
}

type Info struct {
	ID              string
	Containers      int64
	DockerRootDir   string
	Driver          string
	DriverStatus    [][]string
	ExecutionDriver string
	Images          int64
	KernelVersion   string
	OperatingSystem string
	NCPU            int64
	MemTotal        int64
	Name            string
	Labels          []string
}

type ImageDelete struct {
	Deleted  string
	Untagged string
}

type AttachOptions struct {
	Logs   bool
	Stream bool
	Stdin  bool
	Stdout bool
	Stderr bool
}

type CommitOptions struct {
	Container string
	Repo      string
	Tag       string
	Comment   string
	Author    string
}

type ContainerChange struct {
	Kind int
	Path string
}

type TagOptions struct {
	Repo  string
	Force bool
	Tag   string
}

type Stats struct {
	Read         time.Time    `json:"read"`
	NetworkStats NetworkStats `json:"network,omitempty"`
	CpuStats     CpuStats     `json:"cpu_stats,omitempty"`
	MemoryStats  MemoryStats  `json:"memory_stats,omitempty"`
	BlkioStats   BlkioStats   `json:"blkio_stats,omitempty"`
}

type NetworkStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

type CpuStats struct {
	CpuUsage       CpuUsage       `json:"cpu_usage"`
	SystemUsage    uint64         `json:"system_cpu_usage"`
	ThrottlingData ThrottlingData `json:"throttling_data,omitempty"`
}

type MemoryStats struct {
	Usage    uint64     `json:"usage"`
	MaxUsage uint64     `json:"max_usage"`
	Stats    MemDetails `json:"stats"`
	Failcnt  uint64     `json:"failcnt"`
	Limit    uint64     `json:"limit"`
}

type MemDetails struct {
	TotalPgmajFault         uint64 `json:"total_pgmajfault"`
	Cache                   uint64 `json:"cache"`
	MappedFile              uint64 `json:"mapped_file"`
	TotalInactiveFile       uint64 `json:"total_inactive_file"`
	PgpgOut                 uint64 `json:"pgpgout"`
	Rss                     uint64 `json:"rss"`
	TotalMappedFile         uint64 `json:"total_mapped_file"`
	Writeback               uint64 `json:"writeback"`
	Unevictable             uint64 `json:"unevictable"`
	PgpgIn                  uint64 `json:"pgpgin"`
	TotalUnevictable        uint64 `json:"total_unevictable"`
	PgmajFault              uint64 `json:"pgmajfault"`
	TotalRss                uint64 `json:"total_rss"`
	TotalRssHuge            uint64 `json:"total_rss_huge"`
	TotalWriteback          uint64 `json:"total_writeback"`
	TotalInactiveAnon       uint64 `json:"total_inactive_anon"`
	RssHuge                 uint64 `json:"rss_huge"`
	HierarchicalMemoryLimit uint64 `json:"hierarchical_memory_limit"`
	TotalPgFault            uint64 `json:"total_pgfault"`
	TotalActiveFile         uint64 `json:"total_active_file"`
	ActiveAnon              uint64 `json:"active_anon"`
	TotalActiveAnon         uint64 `json:"total_active_anon"`
	TotalPgpgOut            uint64 `json:"total_pgpgout"`
	TotalCache              uint64 `json:"total_cache"`
	InactiveAnon            uint64 `json:"inactive_anon"`
	ActiveFile              uint64 `json:"active_file"`
	PgFault                 uint64 `json:"pgfault"`
	InactiveFile            uint64 `json:"inactive_file"`
	TotalPgpgIn             uint64 `json:"total_pgpgin"`
}

type BlkioStats struct {
	// number of bytes tranferred to and from the block device
	IoServiceBytesRecursive []BlkioStatEntry `json:"io_service_bytes_recursive"`
	IoServicedRecursive     []BlkioStatEntry `json:"io_serviced_recursive"`
	IoQueuedRecursive       []BlkioStatEntry `json:"io_queue_recursive"`
	IoServiceTimeRecursive  []BlkioStatEntry `json:"io_service_time_recursive"`
	IoWaitTimeRecursive     []BlkioStatEntry `json:"io_wait_time_recursive"`
	IoMergedRecursive       []BlkioStatEntry `json:"io_merged_recursive"`
	IoTimeRecursive         []BlkioStatEntry `json:"io_time_recursive"`
	SectorsRecursive        []BlkioStatEntry `json:"sectors_recursive"`
}

type BlkioStatEntry struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

type CpuUsage struct {
	// Total CPU time consumed.
	// Units: nanoseconds.
	TotalUsage uint64 `json:"total_usage"`
	// Total CPU time consumed per core.
	// Units: nanoseconds.
	PercpuUsage []uint64 `json:"percpu_usage"`
	// Time spent by tasks of the cgroup in kernel mode.
	// Units: nanoseconds.
	UsageInKernelmode uint64 `json:"usage_in_kernelmode"`
	// Time spent by tasks of the cgroup in user mode.
	// Units: nanoseconds.
	UsageInUsermode uint64 `json:"usage_in_usermode"`
}

type ThrottlingData struct {
	// Number of periods with throttling active
	Periods uint64 `json:"periods"`
	// Number of periods when the container hit its throttling limit.
	ThrottledPeriods uint64 `json:"throttled_periods"`
	// Aggregate time the container was throttled for in nanoseconds.
	ThrottledTime uint64 `json:"throttled_time"`
}
