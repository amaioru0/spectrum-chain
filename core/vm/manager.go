// At the top of the file, fix your imports:
package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/amaioru0/spectrum-chain/core/network"
	"github.com/amaioru0/spectrum-chain/core/utils"
	"github.com/docker/docker/client"
	"github.com/libvirt/libvirt-go" // Make sure this import exists
)

// ResourceAllocation tracks resources allocated to the global VM
type ResourceAllocation struct {
	CPUCores    int    `json:"cpu_cores"`
	MemoryMB    int    `json:"memory_mb"`
	StorageGB   int    `json:"storage_gb"`
	NetworkKbps int    `json:"network_kbps"`
	NodeID      string `json:"node_id"`
	Timestamp   int64  `json:"timestamp"`
	Signature   []byte `json:"signature"`
}

// VMState represents the current state of the global VM
type VMState struct {
	NodeContributions map[string]ResourceAllocation `json:"node_contributions"`
	TotalCPU          int                           `json:"total_cpu"`
	TotalMemory       int                           `json:"total_memory"`
	TotalStorage      int                           `json:"total_storage"`
	TotalNetwork      int                           `json:"total_network"`
	VMStatus          string                        `json:"vm_status"` // "running", "stopped", "error"
	CreatedAt         int64                         `json:"created_at"`
	UpdatedAt         int64                         `json:"updated_at"`
}

// Manager handles the distributed VM operations
type Manager struct {
	dataDir         string
	networkManager  *network.NetworkManager
	docker          *client.Client
	libvirt         *libvirt.Connect
	state           VMState
	stateLock       sync.RWMutex
	vmRunning       bool
	vmLock          sync.Mutex
	resourceMonitor *ResourceMonitor
	sshServer       *SSHServer
}

// ResourceMonitor continuously monitors and reports node resources
type ResourceMonitor struct {
	manager    *Manager
	interval   time.Duration
	stopChan   chan struct{}
	privateKey []byte // For signing resource contributions
	nodeID     string
}

// SSHServer provides SSH access to the global VM
type SSHServer struct {
	port       int
	vmManager  *Manager
	listenAddr string
	listener   net.Listener
	running    bool
	lock       sync.Mutex
}

// NewManager creates a new VM manager
func NewManager(dataDir string, networkManager *network.NetworkManager) (*Manager, error) {
	// Initialize Docker client
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Initialize libvirt connection
	libvirtConn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}

	// Create VM data directory
	vmDir := filepath.Join(dataDir, "vm")
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create VM directory: %w", err)
	}

	// Create manager instance
	manager := &Manager{
		dataDir:        vmDir,
		networkManager: networkManager,
		docker:         dockerClient,
		libvirt:        libvirtConn,
		state: VMState{
			NodeContributions: make(map[string]ResourceAllocation),
			VMStatus:          "stopped",
			CreatedAt:         time.Now().Unix(),
			UpdatedAt:         time.Now().Unix(),
		},
	}

	// Initialize resource monitor
	nodeID := utils.GenerateRandomID()
	privateKey, err := utils.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	manager.resourceMonitor = &ResourceMonitor{
		manager:    manager,
		interval:   30 * time.Second,
		stopChan:   make(chan struct{}),
		privateKey: privateKey,
		nodeID:     nodeID,
	}

	// Initialize SSH server
	manager.sshServer = &SSHServer{
		port:       2222,
		vmManager:  manager,
		listenAddr: "0.0.0.0",
	}

	// Load existing VM state if available
	if err := manager.loadState(); err != nil {
		log.Printf("No existing VM state found, starting fresh: %v", err)
	}

	return manager, nil
}

// Start starts the VM manager and its components
func (m *Manager) Start(ctx context.Context) error {
	// Start resource monitoring
	go m.resourceMonitor.Start()

	// Register message handlers for VM-related messages
	m.networkManager.RegisterMessageHandler("vm_resource_contribution", m.handleResourceContribution)
	m.networkManager.RegisterMessageHandler("vm_state_request", m.handleStateRequest)
	m.networkManager.RegisterMessageHandler("vm_state_response", m.handleStateResponse)

	// Request current VM state from network
	m.requestVMState()

	// Start the SSH server if VM is running
	m.vmLock.Lock()
	if m.vmRunning {
		if err := m.sshServer.Start(); err != nil {
			log.Printf("Failed to start SSH server: %v", err)
		}
	}
	m.vmLock.Unlock()

	// Start background goroutine to update VM based on resource changes
	go m.runVMUpdateLoop(ctx)

	return nil
}

// Stop stops the VM manager and its components
func (m *Manager) Stop(ctx context.Context) error {
	// Stop resource monitoring
	m.resourceMonitor.Stop()

	// Stop SSH server
	if err := m.sshServer.Stop(); err != nil {
		log.Printf("Error stopping SSH server: %v", err)
	}

	// Stop VM if running
	m.vmLock.Lock()
	defer m.vmLock.Unlock()

	if m.vmRunning {
		if err := m.stopVM(); err != nil {
			log.Printf("Error stopping VM: %v", err)
		}
	}

	// Save current state
	if err := m.saveState(); err != nil {
		log.Printf("Error saving VM state: %v", err)
	}

	// Close connections
	if err := m.libvirt.Close(); err != nil {
		log.Printf("Error closing libvirt connection: %v", err)
	}

	return nil
}

// AllocateResources allocates resources from this node to the global VM
func (m *Manager) AllocateResources(cpu int, memory int, storage int, network int) error {
	// Create resource allocation
	allocation := ResourceAllocation{
		CPUCores:    cpu,
		MemoryMB:    memory,
		StorageGB:   storage,
		NetworkKbps: network,
		NodeID:      m.resourceMonitor.nodeID,
		Timestamp:   time.Now().Unix(),
	}

	// Sign the allocation
	allocationData, err := json.Marshal(allocation)
	if err != nil {
		return fmt.Errorf("failed to marshal allocation: %w", err)
	}

	signature, err := utils.Sign(allocationData, m.resourceMonitor.privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign allocation: %w", err)
	}

	allocation.Signature = signature

	// Update local state
	m.stateLock.Lock()
	m.state.NodeContributions[m.resourceMonitor.nodeID] = allocation
	m.updateTotalResources()
	m.state.UpdatedAt = time.Now().Unix()
	m.stateLock.Unlock()

	// Broadcast to network
	return m.broadcastResourceContribution(allocation)
}

// GetVMState returns the current VM state
func (m *Manager) GetVMState() VMState {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()

	return m.state
}

// IsVMRunning returns whether the global VM is running
func (m *Manager) IsVMRunning() bool {
	m.vmLock.Lock()
	defer m.vmLock.Unlock()

	return m.vmRunning
}

// StartVM starts the global VM
func (m *Manager) StartVM() error {
	m.vmLock.Lock()
	defer m.vmLock.Unlock()

	if m.vmRunning {
		return fmt.Errorf("VM is already running")
	}

	// Check if we have sufficient resources
	m.stateLock.RLock()
	totalCPU := m.state.TotalCPU
	totalMemory := m.state.TotalMemory
	totalStorage := m.state.TotalStorage
	m.stateLock.RUnlock()

	if totalCPU < 1 || totalMemory < 1024 || totalStorage < 10 {
		return fmt.Errorf("insufficient resources to start VM: CPU=%d, Memory=%dMB, Storage=%dGB", totalCPU, totalMemory, totalStorage)
	}

	// Create VM using libvirt
	// This is a simplified version - a real implementation would require more complex setup
	if err := m.createAndStartVM(); err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	// Update state
	m.vmRunning = true

	m.stateLock.Lock()
	m.state.VMStatus = "running"
	m.state.UpdatedAt = time.Now().Unix()
	m.stateLock.Unlock()

	// Start SSH server
	if err := m.sshServer.Start(); err != nil {
		log.Printf("Failed to start SSH server: %v", err)
	}

	// Save state
	return m.saveState()
}

// StopVM stops the global VM
func (m *Manager) StopVM() error {
	m.vmLock.Lock()
	defer m.vmLock.Unlock()

	return m.stopVM()
}

// stopVM is the internal implementation of StopVM (without locking)
func (m *Manager) stopVM() error {
	if !m.vmRunning {
		return nil
	}

	// Stop the VM using libvirt
	// This is a simplified version
	if err := m.shutdownVM(); err != nil {
		return fmt.Errorf("failed to stop VM: %w", err)
	}

	// Update state
	m.vmRunning = false

	m.stateLock.Lock()
	m.state.VMStatus = "stopped"
	m.state.UpdatedAt = time.Now().Unix()
	m.stateLock.Unlock()

	// Stop SSH server
	if err := m.sshServer.Stop(); err != nil {
		log.Printf("Failed to stop SSH server: %v", err)
	}

	// Save state
	return m.saveState()
}

// createAndStartVM creates and starts the global VM
func (m *Manager) createAndStartVM() error {
	// Get total resources
	m.stateLock.RLock()
	totalCPU := m.state.TotalCPU
	totalMemory := m.state.TotalMemory
	totalStorage := m.state.TotalStorage
	m.stateLock.RUnlock()

	// Prepare VM XML definition
	vmXML := fmt.Sprintf(`
		<domain type='kvm'>
			<name>spectrum-global-vm</name>
			<memory unit='MiB'>%d</memory>
			<vcpu>%d</vcpu>
			<os>
				<type arch='x86_64'>hvm</type>
				<boot dev='hd'/>
			</os>
			<devices>
				<disk type='file' device='disk'>
					<driver name='qemu' type='qcow2'/>
					<source file='%s'/>
					<target dev='vda' bus='virtio'/>
				</disk>
				<interface type='bridge'>
					<source bridge='virbr0'/>
					<model type='virtio'/>
				</interface>
				<graphics type='vnc' port='-1' autoport='yes'/>
			</devices>
		</domain>
	`, totalMemory, totalCPU, filepath.Join(m.dataDir, "ubuntu-vm.qcow2"))

	// Check if image exists, if not download/create it
	imagePath := filepath.Join(m.dataDir, "ubuntu-vm.qcow2")
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		if err := m.prepareVMImage(imagePath, totalStorage); err != nil {
			return fmt.Errorf("failed to prepare VM image: %w", err)
		}
	}

	// Define and start the VM
	domain, err := m.libvirt.DomainDefineXML(vmXML)
	if err != nil {
		return fmt.Errorf("failed to define VM: %w", err)
	}

	if err := domain.Create(); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	return nil
}

// prepareVMImage creates or downloads a VM image
func (m *Manager) prepareVMImage(imagePath string, sizeGB int) error {
	// Create a base Ubuntu image using qemu-img
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", imagePath, fmt.Sprintf("%dG", sizeGB))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create VM image: %w", err)
	}

	// Use virt-install to install Ubuntu on the image
	// This is a simplified example - in a real implementation, this would be more complex
	installCmd := exec.Command(
		"virt-install",
		"--name", "temp-ubuntu-install",
		"--ram", "2048",
		"--disk", fmt.Sprintf("path=%s,format=qcow2", imagePath),
		"--vcpus", "2",
		"--os-type", "linux",
		"--os-variant", "ubuntu20.04",
		"--network", "bridge=virbr0",
		"--graphics", "none",
		"--console", "pty,target_type=serial",
		"--location", "http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/",
		"--extra-args", "console=ttyS0,115200n8 serial",
		"--initrd-inject", filepath.Join(m.dataDir, "preseed.cfg"),
		"--noreboot",
	)

	// Create a preseed file for automated installation
	if err := m.createPreseedFile(); err != nil {
		return fmt.Errorf("failed to create preseed file: %w", err)
	}

	// Run the installation (this would normally take quite some time)
	// In a real implementation, this would be done asynchronously
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Ubuntu: %w", err)
	}

	return nil
}

// createPreseedFile creates a preseed file for automated Ubuntu installation
func (m *Manager) createPreseedFile() error {
	preseedContent := `
# Preseed file for automated Ubuntu installation
d-i debian-installer/locale string en_US
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string spectrum-vm
d-i netcfg/get_domain string local
d-i passwd/user-fullname string Spectrum User
d-i passwd/username string spectrum
d-i passwd/user-password password spectrum
d-i passwd/user-password-again password spectrum
d-i time/zone string UTC
d-i partman-auto/method string lvm
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto-lvm/guided_size string max
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i pkgsel/include string openssh-server
d-i pkgsel/upgrade select full-upgrade
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string default
d-i finish-install/reboot_in_progress note
`

	return os.WriteFile(filepath.Join(m.dataDir, "preseed.cfg"), []byte(preseedContent), 0644)
}

// shutdownVM shuts down the global VM
func (m *Manager) shutdownVM() error {
	domain, err := m.libvirt.LookupDomainByName("spectrum-global-vm")
	if err != nil {
		return fmt.Errorf("failed to find VM: %w", err)
	}
	defer domain.Free()

	if err := domain.Shutdown(); err != nil {
		// Force shutdown if graceful shutdown fails
		if err := domain.Destroy(); err != nil {
			return fmt.Errorf("failed to force shutdown VM: %w", err)
		}
	}

	return nil
}

// updateTotalResources recalculates total resources from all contributions
func (m *Manager) updateTotalResources() {
	totalCPU := 0
	totalMemory := 0
	totalStorage := 0
	totalNetwork := 0

	for _, allocation := range m.state.NodeContributions {
		totalCPU += allocation.CPUCores
		totalMemory += allocation.MemoryMB
		totalStorage += allocation.StorageGB
		totalNetwork += allocation.NetworkKbps
	}

	m.state.TotalCPU = totalCPU
	m.state.TotalMemory = totalMemory
	m.state.TotalStorage = totalStorage
	m.state.TotalNetwork = totalNetwork
}

// saveState saves the VM state to disk
func (m *Manager) saveState() error {
	m.stateLock.RLock()
	stateData, err := json.Marshal(m.state)
	m.stateLock.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal VM state: %w", err)
	}

	statePath := filepath.Join(m.dataDir, "vm_state.json")
	if err := os.WriteFile(statePath, stateData, 0644); err != nil {
		return fmt.Errorf("failed to write VM state: %w", err)
	}

	return nil
}

// loadState loads the VM state from disk
func (m *Manager) loadState() error {
	statePath := filepath.Join(m.dataDir, "vm_state.json")
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("failed to read VM state: %w", err)
	}

	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	if err := json.Unmarshal(stateData, &m.state); err != nil {
		return fmt.Errorf("failed to unmarshal VM state: %w", err)
	}

	// Check if VM is actually running
	domain, err := m.libvirt.LookupDomainByName("spectrum-global-vm")
	if err == nil {
		state, _, err := domain.GetState()
		domain.Free()

		if err == nil && state == libvirt.DOMAIN_RUNNING {
			m.vmRunning = true
		}
	}

	return nil
}

// runVMUpdateLoop periodically checks resources and updates the VM
func (m *Manager) runVMUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if VM resources need to be adjusted
			m.stateLock.RLock()
			totalCPU := m.state.TotalCPU
			totalMemory := m.state.TotalMemory
			vmStatus := m.state.VMStatus
			m.stateLock.RUnlock()

			m.vmLock.Lock()

			// If resources are sufficient but VM is not running, start it
			if vmStatus == "stopped" && totalCPU >= 1 && totalMemory >= 1024 && !m.vmRunning {
				if err := m.startVM(); err != nil {
					log.Printf("Failed to start VM automatically: %v", err)
				}
			}

			// If VM is running, check if resources need to be adjusted
			if m.vmRunning {
				if err := m.adjustVMResources(); err != nil {
					log.Printf("Failed to adjust VM resources: %v", err)
				}
			}

			m.vmLock.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

// adjustVMResources adjusts the VM resources based on current allocations
func (m *Manager) adjustVMResources() error {
	// Get the current VM domain
	domain, err := m.libvirt.LookupDomainByName("spectrum-global-vm")
	if err != nil {
		return fmt.Errorf("failed to find VM domain: %w", err)
	}
	defer domain.Free()

	// Get current total resources
	m.stateLock.RLock()
	totalCPU := m.state.TotalCPU
	totalMemory := m.state.TotalMemory
	m.stateLock.RUnlock()

	// Adjust vCPU count if needed
	if err := domain.SetVcpusFlags(uint(totalCPU), libvirt.DOMAIN_VCPU_LIVE); err != nil {
		log.Printf("Failed to adjust vCPU count: %v", err)
	}

	// Adjust memory if needed
	if err := domain.SetMemoryFlags(uint64(totalMemory)*1024, libvirt.DOMAIN_MEM_LIVE); err != nil {
		log.Printf("Failed to adjust memory: %v", err)
	}

	return nil
}

// requestVMState requests the current VM state from the network
func (m *Manager) requestVMState() {
	// Create state request message
	msg := network.Message{
		Type:      "vm_state_request",
		Timestamp: time.Now().Unix(),
		Sender:    m.resourceMonitor.nodeID,
	}

	// Broadcast the request
	if err := m.networkManager.BroadcastMessage(&msg); err != nil {
		log.Printf("Failed to broadcast VM state request: %v", err)
	}
}

// broadcastResourceContribution broadcasts a resource contribution to the network
func (m *Manager) broadcastResourceContribution(allocation ResourceAllocation) error {
	// Create contribution message
	allocationData, err := json.Marshal(allocation)
	if err != nil {
		return fmt.Errorf("failed to marshal allocation: %w", err)
	}

	msg := network.Message{
		Type:      "vm_resource_contribution",
		Data:      allocationData,
		Timestamp: time.Now().Unix(),
		Sender:    m.resourceMonitor.nodeID,
	}

	// Broadcast the message
	return m.networkManager.BroadcastMessage(&msg)
}

// handleResourceContribution handles resource contribution messages from other nodes
func (m *Manager) handleResourceContribution(msg *network.Message) error {
	// Parse the contribution
	var allocation ResourceAllocation
	if err := json.Unmarshal(msg.Data, &allocation); err != nil {
		return fmt.Errorf("failed to unmarshal resource contribution: %w", err)
	}

	// Verify the contribution signature
	// In a real implementation, we would verify against the sender's public key
	// For simplicity, we're skipping signature verification here

	// Update local state
	m.stateLock.Lock()
	m.state.NodeContributions[allocation.NodeID] = allocation
	m.updateTotalResources()
	m.state.UpdatedAt = time.Now().Unix()
	m.stateLock.Unlock()

	// Save state
	return m.saveState()
}

// handleStateRequest handles VM state request messages
func (m *Manager) handleStateRequest(msg *network.Message) error {
	// Get current state
	m.stateLock.RLock()
	stateData, err := json.Marshal(m.state)
	m.stateLock.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal VM state: %w", err)
	}

	// Create response message
	response := network.Message{
		Type:      "vm_state_response",
		Data:      stateData,
		Timestamp: time.Now().Unix(),
		Sender:    m.resourceMonitor.nodeID,
		Recipient: msg.Sender,
	}

	// Send the response
	return m.networkManager.SendMessage(&response)
}

// handleStateResponse handles VM state response messages
func (m *Manager) handleStateResponse(msg *network.Message) error {
	// Parse the state
	var remoteState VMState
	if err := json.Unmarshal(msg.Data, &remoteState); err != nil {
		return fmt.Errorf("failed to unmarshal VM state: %w", err)
	}

	// Compare with local state
	m.stateLock.RLock()
	localUpdatedAt := m.state.UpdatedAt
	m.stateLock.RUnlock()

	// Update local state if remote state is newer
	if remoteState.UpdatedAt > localUpdatedAt {
		m.stateLock.Lock()
		m.state = remoteState
		m.stateLock.Unlock()

		// Save updated state
		if err := m.saveState(); err != nil {
			return fmt.Errorf("failed to save updated VM state: %w", err)
		}

		// Update VM status
		m.vmLock.Lock()
		if remoteState.VMStatus == "running" && !m.vmRunning {
			if err := m.startVM(); err != nil {
				log.Printf("Failed to start VM based on remote state: %v", err)
			}
		} else if remoteState.VMStatus == "stopped" && m.vmRunning {
			if err := m.stopVM(); err != nil {
				log.Printf("Failed to stop VM based on remote state: %v", err)
			}
		}
		m.vmLock.Unlock()
	}

	return nil
}

// Start starts the resource monitor
func (rm *ResourceMonitor) Start() {
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()

	// Initial resource contribution
	rm.monitorAndReportResources()

	for {
		select {
		case <-ticker.C:
			rm.monitorAndReportResources()
		case <-rm.stopChan:
			return
		}
	}
}

// Stop stops the resource monitor
func (rm *ResourceMonitor) Stop() {
	close(rm.stopChan)
}

// monitorAndReportResources monitors node resources and reports them
func (rm *ResourceMonitor) monitorAndReportResources() {
	// Get available CPU cores
	cpuCores := getAvailableCPUCores()

	// Get available memory in MB
	memoryMB := getAvailableMemory()

	// Get available storage in GB
	storageGB := getAvailableStorage(rm.manager.dataDir)

	// Get available network bandwidth in Kbps
	networkKbps := getAvailableNetworkBandwidth()

	// Report resources
	if err := rm.manager.AllocateResources(cpuCores, memoryMB, storageGB, networkKbps); err != nil {
		log.Printf("Failed to allocate resources: %v", err)
	}
}

// getAvailableCPUCores returns the number of available CPU cores
func getAvailableCPUCores() int {
	// This is a simplified implementation
	// In a real system, we would calculate available cores more accurately

	// Get total number of cores and subtract estimated usage
	totalCores := 4 // Example value

	// Reserve some cores for system operation
	availableCores := totalCores - 1
	if availableCores < 1 {
		availableCores = 1
	}

	return availableCores
}

// getAvailableMemory returns available memory in MB
func getAvailableMemory() int {
	// This is a simplified implementation
	// In a real system, we would read this from /proc/meminfo or similar

	// Example: 8GB total, reserve 2GB for system
	totalMemoryMB := 8 * 1024
	availableMemoryMB := totalMemoryMB - 2*1024

	return availableMemoryMB
}

// getAvailableStorage returns available storage in GB
func getAvailableStorage(dataDir string) int {
	// This is a simplified implementation
	// In a real system, we would use os.StatFS or similar

	// Example: 100GB available
	return 100
}

// getAvailableNetworkBandwidth returns available network bandwidth in Kbps
func getAvailableNetworkBandwidth() int {
	// This is a simplified implementation
	// In a real system, we would measure actual available bandwidth

	// Example: 100 Mbps = 100,000 Kbps
	return 100000
}

// Start starts the SSH server
func (s *SSHServer) Start() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.running {
		return nil
	}

	// Create listener
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.listenAddr, s.port))
	if err != nil {
		return fmt.Errorf("failed to start SSH listener: %w", err)
	}

	s.listener = listener
	s.running = true

	// Handle connections
	go s.handleConnections()

	log.Printf("SSH server started on %s:%d", s.listenAddr, s.port)
	return nil
}

// Stop stops the SSH server
func (s *SSHServer) Stop() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if !s.running {
		return nil
	}

	if err := s.listener.Close(); err != nil {
		return fmt.Errorf("failed to close SSH listener: %w", err)
	}

	s.running = false
	log.Printf("SSH server stopped")
	return nil
}

// handleConnections handles incoming SSH connections
func (s *SSHServer) handleConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if server is shutting down
			s.lock.Lock()
			running := s.running
			s.lock.Unlock()

			if !running {
				return
			}

			log.Printf("Error accepting SSH connection: %v", err)
			continue
		}

		// Handle the connection
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH connection
func (s *SSHServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Check if VM is running
	if !s.vmManager.IsVMRunning() {
		conn.Write([]byte("Global VM is not running. Please try again later.\r\n"))
		return
	}

	// Get VM domain
	domain, err := s.vmManager.libvirt.LookupDomainByName("spectrum-global-vm")
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("Error: %v\r\n", err)))
		return
	}
	defer domain.Free()

	// Get VM IP address
	vmIP, err := s.getVMIPAddress(domain)
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("Error getting VM IP: %v\r\n", err)))
		return
	}

	// Connect to VM SSH
	vmConn, err := net.Dial("tcp", fmt.Sprintf("%s:22", vmIP))
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("Error connecting to VM SSH: %v\r\n", err)))
		return
	}
	defer vmConn.Close()

	// Bidirectional copy
	go func() {
		_, err := io.Copy(vmConn, conn)
		if err != nil {
			log.Printf("Error forwarding to VM: %v", err)
		}
	}()

	_, err = io.Copy(conn, vmConn)
	if err != nil {
		log.Printf("Error forwarding from VM: %v", err)
	}
}

// getVMIPAddress gets the IP address of the VM
func (s *SSHServer) getVMIPAddress(domain *libvirt.Domain) (string, error) {
	// In a real implementation, this would query the libvirt domain for its IP
	// For simplicity, we'll use a placeholder IP
	return "192.168.122.100", nil
}
