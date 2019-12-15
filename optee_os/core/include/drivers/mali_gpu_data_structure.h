typedef struct base_jd_udata {
	u64 blob[2];	 /**< per-job data array */
} base_jd_udata;

typedef u8 base_atom_id; /**< Type big enough to store an atom number in */
typedef u8 base_jd_dep_type;
typedef u8 base_jd_prio;
typedef u32 base_jd_core_req;

struct base_dependency {
	base_atom_id  atom_id;               /**< An atom number */
	base_jd_dep_type dependency_type;    /**< Dependency type */
};

typedef struct sec_base_jd_atom_v2 {
	u64 jc;			    /**< job-chain GPU address */
	struct base_jd_udata udata;		    /**< user data */
	u64 extres_list;	    /**< list of external resources */
	u16 nr_extres;			    /**< nr of external resources or JIT allocations */
	u16 compat_core_req;	            /**< core requirements which correspond to the legacy support for UK 10.2 */
	struct base_dependency pre_dep[2];  /**< pre-dependencies, one need to use SETTER function to assign this field,
	this is done in order to reduce possibility of improper assigment of a dependency field */
	base_atom_id atom_number;	    /**< unique number to identify the atom */
	base_jd_prio prio;                  /**< Atom priority. Refer to @ref base_jd_prio for more details */
	u8 device_nr;			    /**< coregroup when BASE_JD_REQ_SPECIFIC_COHERENT_GROUP specified */
	u8 padding[1];
	base_jd_core_req core_req;          /**< core requirements */
} sec_base_jd_atom_v2;
