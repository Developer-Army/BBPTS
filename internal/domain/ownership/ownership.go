package ownership

// Owner represents the identity of the asset owner.
type Owner struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Team represents a group within the organization.
type Team struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ManagerID *int64 `json:"manager_id"`
}

// BusinessUnit represents the highest organizational division.
type BusinessUnit struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	DirectorID *int64 `json:"director_id"`
}
