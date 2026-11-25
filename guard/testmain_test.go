package guard

import (
	"os"
	"testing"

	"github.com/zakirkun/EyeOfG0d/db"
)

func TestMain(m *testing.M) {
	// Own database per package (#80), as in db, agent, server, evidence and intercept.
	db.SuffixTestDatabase("guard")
	os.Exit(m.Run())
}
