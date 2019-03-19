// +build linux

package cgnetcls

//This package does not use interfaces/objects from other trireme component so we don't need to mock anything here
//We will create actual system objects
//This can be tested only on linux since the directory structure will not exist anywhere else
//Tests here will be skipped if you don't run as root
import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	testcgroupname       = "/test"
	testcgroupnameformat = "test"
	testmark             = 100
	testRootUser         = "root"
)

func cleanupnetclsgroup() {
	data, _ := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, testcgroupname, procs))
	fmt.Println(string(data))
	_ = ioutil.WriteFile(filepath.Join(basePath, procs), data, 0644)
	_ = os.RemoveAll(filepath.Join(basePath, TriremeBasePath, testcgroupname))
}

func TestCreategroup(t *testing.T) {

	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}

	cg := NewCgroupNetController("/tmp", "")
	if err := cg.Creategroup(testcgroupnameformat); err != nil {
		//Check if all the files required are created
		t.Errorf("Failed to create group error returned %s", err.Error())
	}

	defer cleanupnetclsgroup()

	if _, err := ioutil.ReadFile(filepath.Join(basePath, releaseAgentConfFile)); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("ReleaseAgentConf File does not exist.Cgroup mount failed")
			t.SkipNow()
		}
	}

	if val, err := ioutil.ReadFile(filepath.Join(basePath, notifyOnReleaseFile)); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("Notify on release file does not exist.Cgroup mount failed")
			t.SkipNow()
		}
	} else {
		if strings.TrimSpace(string(val)) != "1" {
			t.Errorf("Notify release file in base net_cls not programmed")
			t.SkipNow()
		}
	}

	if val, err := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, notifyOnReleaseFile)); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("Notify on release file does not exist.Cgroup mount failed")
			t.SkipNow()
		}
	} else {
		if strings.TrimSpace(string(val)) != "1" {
			t.Errorf("Notify release file in aporeto base dir /sys/fs/cgroup/aporeto not programmed")
			t.SkipNow()
		}
	}

	if val, err := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, testcgroupname, notifyOnReleaseFile)); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("Notify on release file does not exist.Cgroup mount failed")
			t.SkipNow()
		}
	} else {
		if strings.TrimSpace(string(val)) != "1" {
			t.Errorf("Notify release file in cgroup not programmed")
			t.SkipNow()
		}
	}
}

func TestAssignMark(t *testing.T) {
	cg := NewCgroupNetController("/tmp", "")
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	//Assigning mark before creating group
	if err := cg.AssignMark(testcgroupname, testmark); err == nil {
		t.Errorf("Assign mark succeeded without a valid group being present ")
		t.SkipNow()
	}
	if err := cg.Creategroup(testcgroupnameformat); err != nil {
		t.Errorf("Error creating cgroup %s", err)
		t.SkipNow()
	}

	defer cleanupnetclsgroup()

	if err := cg.AssignMark(testcgroupnameformat, testmark); err != nil {
		t.Errorf("Failed to assign mark error = %s", err.Error())
		t.SkipNow()
	} else {
		data, _ := ioutil.ReadFile(filepath.Join(basePath, TriremeBasePath, testcgroupname, markFile))
		u, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			t.Errorf("Non Integer mark value in classid file")
			t.SkipNow()
		}
		if u != testmark {
			t.Errorf("Unexpected mark val expected %d, read %d", testmark, u)
			t.SkipNow()
		}
	}
}

func TestAddProcess(t *testing.T) {
	//hopefully this pid does not exist
	pid := 1<<31 - 1
	r := rand.New(rand.NewSource(23))
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	cg := NewCgroupNetController("/tmp", "")
	//AddProcess to a non-existent group
	if err := cg.AddProcess(testcgroupname, os.Getpid()); err == nil {
		t.Errorf("Process successfully added to a non existent group")
		t.SkipNow()
	}
	if err := cg.Creategroup(testcgroupnameformat); err != nil {
		t.Errorf("Error creating cgroup")
		t.SkipNow()
	}

	defer cleanupnetclsgroup()

	//Add a non-existent process
	//loop to find non-existent pid
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			break
		}
		pid = r.Int()

	}
	if err := cg.AddProcess(testcgroupnameformat, pid); err != nil {
		t.Errorf("Unexpected error not returned for non-existent process")
		t.SkipNow()
	}
	pid = 1 //Guaranteed to be present
	if err := cg.AddProcess(testcgroupname, pid); err != nil {
		t.Errorf("Failed to add process %s", err.Error())
		t.SkipNow()
	} else {
		//This directory structure should not be delete
		if err := os.RemoveAll(filepath.Join(basePath, TriremeBasePath, testcgroupname)); err == nil {
			t.Errorf("Process not added to cgroup")
			t.SkipNow()
		}
	}
}

func TestRemoveProcess(t *testing.T) {
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	cg := NewCgroupNetController("/tmp", "")
	//Removing process from non-existent group
	if err := cg.RemoveProcess(testcgroupname, 1); err == nil {
		t.Errorf("RemoveProcess succeeded without valid group being present ")
		t.SkipNow()
	}
	if err := cg.Creategroup(testcgroupnameformat); err != nil {
		t.Errorf("Error creating cgroup")
		t.SkipNow()
	}

	defer cleanupnetclsgroup()

	if err := cg.AddProcess(testcgroupname, 1); err != nil {
		t.Errorf("Error adding process")
		t.SkipNow()
	}
	if err := cg.RemoveProcess(testcgroupnameformat, 10); err == nil {
		t.Errorf("Removed process which was not a part of this cgroup")
		t.SkipNow()
	}
	if err := cg.RemoveProcess(testcgroupname, 1); err != nil {
		t.Errorf("Failed to remove process %s", err.Error())
		t.SkipNow()
	}
}

func TestDeleteCgroup(t *testing.T) {
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	cg := NewCgroupNetController("/tmp", "")
	//Removing process from non-existent group
	if err := cg.DeleteCgroup(testcgroupnameformat); err != nil {
		t.Errorf("Non-existent cgroup delelte returned an error")
		t.SkipNow()
	}
	if err := cg.Creategroup(testcgroupname); err != nil {
		t.Errorf("Failed to create cgroup %s", err.Error())
		t.SkipNow()
	}

	defer cleanupnetclsgroup()

	if err := cg.DeleteCgroup(testcgroupname); err != nil {
		t.Errorf("Failed to delete cgroup %s", err.Error())
		t.SkipNow()
	}

}

func TestDeleteBasePath(t *testing.T) {
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	cg := NewCgroupNetController("/tmp", "")
	//Removing process from non-existent group
	if err := cg.DeleteCgroup(testcgroupname); err != nil {
		t.Errorf("Delete of group failed %s", err.Error())
	}

	defer cleanupnetclsgroup()

	cg.Deletebasepath(testcgroupnameformat)
	_, err := os.Stat(filepath.Join(basePath, TriremeBasePath, testcgroupname))
	if err == nil {
		t.Errorf("Delete of cgroup from system failed")
		t.SkipNow()
	}
}

func TestListCgroupProcesses(t *testing.T) {
	pid := 1<<31 - 1
	r := rand.New(rand.NewSource(23))
	if os.Getenv("USER") != testRootUser {
		t.SkipNow()
	}
	cg := NewCgroupNetController("/tmp", "")

	_, err := cg.ListCgroupProcesses(testcgroupname)
	if err == nil {
		t.Errorf("No process found but succeeded")
	}
	//AddProcess to a non-existent group
	if err = cg.AddProcess(testcgroupname, os.Getpid()); err == nil {
		t.Errorf("Process successfully added to a non existent group")
		t.SkipNow()
	}
	if err = cg.Creategroup(testcgroupname); err != nil {
		t.Errorf("Error creating cgroup")
		t.SkipNow()
	}

	defer cleanupnetclsgroup()

	//Add a non-existent process
	//loop to find non-existent pid
	for {
		if err = syscall.Kill(pid, 0); err != nil {
			break
		}
		pid = r.Int()

	}

	pid = 1 //Guaranteed to be present
	if err = cg.AddProcess(testcgroupname, pid); err != nil {
		t.Errorf("Failed to add process %s", err.Error())
		t.SkipNow()
	} else {
		//This directory structure should not be delete
		if err = os.RemoveAll(filepath.Join(basePath, TriremeBasePath, testcgroupname)); err == nil {
			t.Errorf("Process not added to cgroup")
			t.SkipNow()
		}
	}

	procs, err := cg.ListCgroupProcesses(testcgroupname)
	if procs[0] != "1" && err != nil {
		t.Errorf("No process found %d", err)
	}
}
