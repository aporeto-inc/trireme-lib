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
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	testcgroupname = "/test"
	testmark       = 100
)

func cleanupnetclsgroup() {
	data, _ := ioutil.ReadFile(basePath + TriremeBasePath + testcgroupname + procs)
	fmt.Println(string(data))
	ioutil.WriteFile(basePath+procs, data, 0644)
	os.RemoveAll(basePath + TriremeBasePath + testcgroupname)
}
func TestCreategroup(t *testing.T) {

	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}

	cg := NewCgroupNetController("")
	err := cg.Creategroup(testcgroupname)
	defer cleanupnetclsgroup()

	//Check if all the files required are created
	if err != nil {
		t.Errorf("Failed to create group error returned %s", err.Error())
	}

	if _, err := ioutil.ReadFile(basePath + releaseAgentConfFile); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("ReleaseAgentConf File does not exist.Cgroup mount failed")
			t.SkipNow()
		}
	}

	if val, err := ioutil.ReadFile(basePath + notifyOnReleaseFile); err != nil {
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

	if val, err := ioutil.ReadFile(basePath + TriremeBasePath + notifyOnReleaseFile); err != nil {
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

	if val, err := ioutil.ReadFile(basePath + TriremeBasePath + testcgroupname + notifyOnReleaseFile); err != nil {
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

	return

}

func TestAssignMark(t *testing.T) {
	cg := NewCgroupNetController("")
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}
	//Assigning mark before creating group
	err := cg.AssignMark(testcgroupname, testmark)
	if err == nil {
		t.Errorf("Assign mark succeeded without a valid group being present ")
		t.SkipNow()
	}
	cg.Creategroup(testcgroupname)
	defer cleanupnetclsgroup()
	err = cg.AssignMark(testcgroupname, testmark)
	if err != nil {
		t.Errorf("Failed to assign mark error = %s", err.Error())
		t.SkipNow()
	} else {
		data, _ := ioutil.ReadFile(basePath + TriremeBasePath + testcgroupname + markFile)
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
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}
	cg := NewCgroupNetController("")
	//AddProcess to a non-existent group
	err := cg.AddProcess(testcgroupname, os.Getpid())
	if err == nil {
		t.Errorf("Process successfully added to a non existent group")
		t.SkipNow()
	}
	cg.Creategroup(testcgroupname)
	defer cleanupnetclsgroup()
	//Add a non-existent process
	//loop to find non-existent pid
	for {
		if err = syscall.Kill(pid, 0); err != nil {
			break
		}
		pid = r.Int()

	}
	err = cg.AddProcess(testcgroupname, pid)
	if err != nil {
		t.Errorf("Unexpected error not returned for non-existent process")
		t.SkipNow()
	}
	pid = 1 //Guaranteed to be present
	err = cg.AddProcess(testcgroupname, pid)
	if err != nil {
		t.Errorf("Failed to add process %s", err.Error())
		t.SkipNow()
	} else {
		//This directory structure should not be delete
		err = os.RemoveAll(basePath + TriremeBasePath + testcgroupname)
		if err == nil {
			t.Errorf("Process not added to cgroup")
			t.SkipNow()
		}
	}

}

func TestRemoveProcess(t *testing.T) {
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}
	cg := NewCgroupNetController("")
	//Removing process from non-existent group
	err := cg.RemoveProcess(testcgroupname, 1)
	if err == nil {
		t.Errorf("RemoveProcess succeeded without valid group being present ")
		t.SkipNow()
	}
	cg.Creategroup(testcgroupname)
	defer cleanupnetclsgroup()
	cg.AddProcess(testcgroupname, 1)
	err = cg.RemoveProcess(testcgroupname, 10)
	if err == nil {
		t.Errorf("Removed process which was not a part of this cgroup")
		t.SkipNow()
	}
	err = cg.RemoveProcess(testcgroupname, 1)
	if err != nil {
		t.Errorf("Failed to remove process %s", err.Error())
		t.SkipNow()
	}
}

func TestDeleteCgroup(t *testing.T) {
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}
	cg := NewCgroupNetController("")
	//Removing process from non-existent group
	err := cg.DeleteCgroup(testcgroupname)
	if err != nil {
		t.Errorf("Non-existent cgroup delelte returned an error")
		t.SkipNow()
	}
	cg.Creategroup(testcgroupname)
	defer cleanupnetclsgroup()
	err = cg.DeleteCgroup(testcgroupname)
	if err != nil {
		t.Errorf("Failed to delete cgroup %s", err.Error())
		t.SkipNow()
	}

}

func TestDeleteBasePath(t *testing.T) {
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}
	cg := NewCgroupNetController("")
	//Removing process from non-existent group
	err := cg.DeleteCgroup(testcgroupname)
	if err != nil {
		t.Errorf("Delete of group failed %s", err.Error())
	}

	defer cleanupnetclsgroup()
	cg.Deletebasepath(testcgroupname)
	_, err = os.Stat(basePath + TriremeBasePath + testcgroupname)
	if err == nil {
		t.Errorf("Delete of cgroup from system failed %s", err.Error())
		t.SkipNow()
	}
}
